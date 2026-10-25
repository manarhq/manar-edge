package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// parseToken splits `<tenant>:<agent>:<secret>` like manar-api's enrollment-token util.
func parseToken(tok string) (tenant, agent string, ok bool) {
	parts := strings.Split(tok, ":")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// makeCSR generates an ECDSA P-256 key and a CSR whose only SAN is the URI identifier
// `agent://<tenant>/<agent>`, the same as manar-agents and sdk-node.
func makeCSR(identifier string) (keyPEM, csrPEM []byte, err error) {
	u, err := url.Parse(identifier)
	if err != nil {
		return nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: identifier},
		URIs:    []*url.URL{u},
	}, key)
	if err != nil {
		return nil, nil, err
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

type enrollResponse struct {
	Certificate string `json:"certificate"`
	CAChain     string `json:"caChain"`
	NotAfter    string `json:"notAfter"`
	Edge        *Edge  `json:"edge"`
}

func cmdEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	api := fs.String("api", "", "Manar console or API base URL (https)")
	token := fs.String("token", "", "enrollment token <tenant>:<agent>:<secret>; \"-\" reads it from stdin")
	base := fs.String("state-dir", defaultStateBase, "state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *api == "" || *token == "" || fs.NArg() != 0 {
		return errors.New("usage: manar-edge enroll --api <url> --token <tenant:agent:secret|-> [--state-dir D]")
	}
	if err := requireAdmin(); err != nil {
		return err
	}
	tok := *token
	if tok == "-" {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		tok = strings.TrimSpace(line)
	}
	tenant, agent, ok := parseToken(tok)
	if !ok {
		return errors.New("malformed enrollment token: expected <tenant>:<agent>:<secret>")
	}
	if !slugPattern.MatchString(tenant) || !slugPattern.MatchString(agent) {
		return errors.New("enrollment token has a tenant or agent slug this host does not accept")
	}
	apiURL, err := checkAPIURL(*api)
	if err != nil {
		return err
	}

	name := edgeName(tenant, agent)
	dir := agentDir(*base, name)
	if err := secureMkdir(*base); err != nil {
		return err
	}
	if err := secureMkdir(dir); err != nil {
		return err
	}

	keyPEM, csrPEM, err := makeCSR("agent://" + tenant + "/" + agent)
	if err != nil {
		return err
	}
	wgKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	resp, err := postEnroll(ctx, http.DefaultClient, apiURL, tok, string(csrPEM), wgKey.PublicKey().String())
	if err != nil {
		return err
	}
	if err := validateEdge(resp.Edge); err != nil {
		return err
	}

	prev, _ := loadState(dir)
	st := &State{
		Name: name, TenantSlug: tenant, AgentSlug: agent,
		WGPublicKey: wgKey.PublicKey().String(), Edge: *resp.Edge,
		EnrolledAt: time.Now().UTC().Format(time.RFC3339), NotAfter: resp.NotAfter,
	}
	if prev != nil {
		st.Task, st.Programs = prev.Task, prev.Programs
	}
	for _, f := range []struct {
		name string
		data []byte
	}{
		{fileKey, keyPEM},
		{fileCert, []byte(resp.Certificate)},
		{fileCA, []byte(resp.CAChain)},
		{fileWGKey, []byte(wgKey.String() + "\n")},
	} {
		if err := writePrivate(filepath.Join(dir, f.name), f.data); err != nil {
			return err
		}
	}
	if err := saveState(dir, st); err != nil {
		return err
	}
	fmt.Printf("enrolled %s/%s as %s (overlay %s)\nnext: manar-edge up %s --task <taskId>\n",
		tenant, agent, name, st.Edge.Address, name)
	return nil
}

// checkAPIURL refuses to send the token in clear text except to a loopback address.
func checkAPIURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Host == "" {
		return nil, errors.New("--api must be an absolute URL")
	}
	if u.Scheme == "https" {
		return u, nil
	}
	if ip, err := netip.ParseAddr(u.Hostname()); u.Scheme == "http" && (u.Hostname() == "localhost" || (err == nil && ip.IsLoopback())) {
		return u, nil
	}
	return nil, errors.New("--api must use https (http is accepted only for a loopback address)")
}

func postEnroll(ctx context.Context, c *http.Client, api *url.URL, token, csr, wgPub string) (*enrollResponse, error) {
	body, _ := json.Marshal(map[string]any{"token": token, "csr": csr, "edge": map[string]string{"wgPublicKey": wgPub}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api.String()+"/agents/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enrollment request failed: %w", err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode/100 != 2 {
		return nil, fmt.Errorf("enrollment refused: HTTP %d: %s", res.StatusCode, serverMessage(b))
	}
	var out enrollResponse
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("enrollment response is not JSON: %w", err)
	}
	if out.Certificate == "" || out.CAChain == "" {
		return nil, errors.New("enrollment response has no certificate or caChain")
	}
	if out.Edge == nil {
		return nil, errors.New("enrollment response has no edge object: edge is not enabled on this Manar install")
	}
	return &out, nil
}

// serverMessage extracts a short, printable error message from an error body.
func serverMessage(b []byte) string {
	var m struct {
		Message any    `json:"message"`
		Error   string `json:"error"`
	}
	if json.Unmarshal(b, &m) == nil && m.Message != nil {
		return fmt.Sprint(m.Message)
	}
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func validateEdge(e *Edge) error {
	if _, err := netip.ParsePrefix(e.Address); err != nil {
		return fmt.Errorf("edge.address %q: %w", e.Address, err)
	}
	if _, err := wgtypes.ParseKey(e.GatewayPublicKey); err != nil {
		return errors.New("edge.gatewayPublicKey is not a WireGuard key")
	}
	for k, v := range map[string]string{"gatewayEndpoint": e.GatewayEndpoint, "proxyAddress": e.ProxyAddress, "manarAddress": e.ManarAddress} {
		if _, _, err := net.SplitHostPort(v); err != nil {
			return fmt.Errorf("edge.%s %q: %w", k, v, err)
		}
	}
	for _, v := range []string{e.ManarAddress, e.ProxyAddress} {
		h, _, _ := net.SplitHostPort(v)
		if _, err := netip.ParseAddr(h); err != nil {
			return fmt.Errorf("edge address %q must be an IP in the overlay", v)
		}
	}
	if e.ManarServerName == "" {
		return errors.New("edge.manarServerName is empty")
	}
	return nil
}
