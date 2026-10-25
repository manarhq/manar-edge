//go:build linux

// Command manar-edge-gateway is the WireGuard gateway agents reach Manar through: the only network
// peer of every governed agent (docs/design.md, section 3).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gitlab.vax.sh/manar/manar-edge/internal/gateway"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var version = "dev"

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println(version)
		return
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("gateway stopped", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	var (
		cidr      = flag.String("edge-cidr", env("MANAR_EDGE_CIDR", "100.88.0.0/16"), "overlay network; the gateway takes its first host")
		iface     = flag.String("interface", env("MANAR_EDGE_INTERFACE", "wg0"), "WireGuard interface name")
		wgPort    = flag.Int("listen-port", 51820, "WireGuard UDP port")
		keyFile   = flag.String("private-key-file", env("MANAR_EDGE_PRIVATE_KEY_FILE", "/etc/manar-edge-gateway/wireguard/private_key"), "WireGuard private key (base64)")
		tokenFile = flag.String("token-file", env("MANAR_EDGE_GATEWAY_TOKEN_FILE", "/etc/manar-edge-gateway/token/gateway_token"), "bearer token for manar-api's /internal/v1/edge API")
		apiURL    = flag.String("api-url", env("MANAR_API_URL", "http://manar-api.manar-prod.svc:3000"), "manar-api HTTP base URL (sync and events API)")
		upstream  = flag.String("agent-upstream", env("MANAR_AGENT_UPSTREAM", "manar-api.manar-prod.svc:3443"), "manar-api agent mTLS listener, relayed from :443")
		ports     = flag.String("proxy-ports", env("MANAR_PROXY_PORTS", "443"), "comma-separated CONNECT ports allowed")
		admin     = flag.String("admin-addr", env("MANAR_ADMIN_ADDR", ":9090"), "health and metrics listener")
		queue     = flag.Int("events-queue", 10000, "egress events kept in memory while manar-api is unreachable")
	)
	flag.Parse()

	overlay, err := netip.ParsePrefix(*cidr)
	if err != nil || !overlay.Addr().Is4() || overlay.Bits() > 30 {
		return fmt.Errorf("edge-cidr %q: want an IPv4 prefix of /30 or larger", *cidr)
	}
	overlay = overlay.Masked()
	gw := overlay.Addr().Next()
	var proxyPorts []int
	for _, s := range strings.Split(*ports, ",") {
		p, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("proxy-ports: bad port %q", s)
		}
		proxyPorts = append(proxyPorts, p)
	}
	keyText, err := os.ReadFile(*keyFile)
	if err != nil {
		return fmt.Errorf("read private key file: %w", err)
	}
	key, err := wgtypes.ParseKey(strings.TrimSpace(string(keyText)))
	if err != nil {
		return errors.New("private key file does not hold a base64 WireGuard key")
	}

	const relayPort, proxyPort = 443, 3128
	kernel, err := gateway.SetupKernel(*iface, netip.PrefixFrom(gw, overlay.Bits()), *wgPort, key, []int{relayPort, proxyPort})
	if err != nil {
		return err
	}
	log.Info("wireguard up", "interface", *iface, "address", gw, "port", *wgPort)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	metrics := &gateway.Metrics{}
	reg := gateway.NewRegistry(overlay, log)
	syncer := &gateway.Syncer{
		APIURL: *apiURL, TokenFile: *tokenFile, Registry: reg, Net: kernel, Metrics: metrics, Log: log,
		Client:     &http.Client{Timeout: 40 * time.Second}, // the server holds a poll up to 25 s
		MinBackoff: 500 * time.Millisecond, MaxBackoff: 30 * time.Second,
	}
	events := &gateway.Events{
		APIURL: *apiURL, TokenFile: *tokenFile, Metrics: metrics, Log: log, Max: *queue,
		Client: &http.Client{Timeout: 10 * time.Second}, Interval: 2 * time.Second,
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	relay := &gateway.Relay{Registry: reg, Upstream: *upstream, Dial: dialer.DialContext, Metrics: metrics, Log: log}
	proxy := &gateway.Proxy{
		Registry: reg, Events: events, Metrics: metrics, Log: log, Ports: proxyPorts, Overlay: overlay,
		Dial: dialer.DialContext,
		Resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
	}

	relayLn, err := net.Listen("tcp4", netip.AddrPortFrom(gw, relayPort).String())
	if err != nil {
		return err
	}
	proxyLn, err := net.Listen("tcp4", netip.AddrPortFrom(gw, proxyPort).String())
	if err != nil {
		return err
	}
	adminSrv := &http.Server{Addr: *admin, Handler: metrics.Handler(syncer.Ready), ReadHeaderTimeout: 5 * time.Second}

	errc := make(chan error, 3)
	go func() { errc <- relay.Serve(relayLn) }()
	go func() { errc <- proxy.Serve(proxyLn) }()
	go func() { errc <- adminSrv.ListenAndServe() }()
	go syncer.Run(ctx)
	eventsDone := make(chan struct{})
	go func() { events.Run(ctx); close(eventsDone) }()

	select {
	case <-ctx.Done():
		log.Info("shutting down")
		err = nil
	case err = <-errc:
		stop()
	}
	relayLn.Close()
	proxyLn.Close()
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	adminSrv.Shutdown(sctx)
	<-eventsDone
	return err
}
