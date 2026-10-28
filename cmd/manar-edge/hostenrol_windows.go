package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Windows side of key-less enrolment. The computer certificate's key is non-exportable, so it is
// used in place: the certificate is found in LocalMachine\My, its CNG key is opened by
// CryptAcquireCertificatePrivateKey and the proof is signed with NCryptSignHash. The host key is
// a persisted machine key in the Microsoft Software Key Storage Provider (a software key).

const (
	softwareKSP    = "Microsoft Software Key Storage Provider"
	hostKeyName    = "ManarEdgeHostKey"
	ncryptMachine  = 0x20       // NCRYPT_MACHINE_KEY_FLAG
	ntePExists     = 0x8009000F // NTE_EXISTS
	nteBadKeyset   = 0x80090016 // NTE_BAD_KEYSET (key not found)
	nteNoKey       = 0x8009000D // NTE_NO_KEY
	bcryptPadPKCS1 = 0x2
	eccPublicP256  = 0x31534345 // BCRYPT_ECDSA_PUBLIC_P256_MAGIC
)

var (
	ncrypt          = windows.NewLazySystemDLL("ncrypt.dll")
	pOpenProvider   = ncrypt.NewProc("NCryptOpenStorageProvider")
	pOpenKey        = ncrypt.NewProc("NCryptOpenKey")
	pCreateKey      = ncrypt.NewProc("NCryptCreatePersistedKey")
	pFinalizeKey    = ncrypt.NewProc("NCryptFinalizeKey")
	pExportKey      = ncrypt.NewProc("NCryptExportKey")
	pSignHash       = ncrypt.NewProc("NCryptSignHash")
	pFreeObject     = ncrypt.NewProc("NCryptFreeObject")
	errNoComputerOK = errors.New("no usable computer certificate in LocalMachine\\My (needs Client Authentication, a domain CA issuer, a private key, RSA 2048+ or P-256/P-384, and to be in date)")
)

func status(name string, r uintptr) error {
	if r == 0 {
		return nil
	}
	return fmt.Errorf("%s failed: 0x%08X", name, uint32(r))
}

// cngSigner signs with a CNG key handle. It is a crypto.Signer for SHA-256 digests.
type cngSigner struct {
	h   uintptr
	pub crypto.PublicKey
}

func (s *cngSigner) Public() crypto.PublicKey { return s.pub }

func (s *cngSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 || len(digest) != 32 {
		return nil, errors.New("only SHA-256 digests are signed")
	}
	var pad unsafe.Pointer
	var flags uintptr
	_, isRSA := s.pub.(*rsa.PublicKey)
	if isRSA {
		alg, _ := windows.UTF16PtrFromString("SHA256")
		pad = unsafe.Pointer(&struct{ alg *uint16 }{alg})
		flags = bcryptPadPKCS1
	}
	call := func(out *byte, n uint32, got *uint32) error {
		r, _, _ := pSignHash.Call(s.h, uintptr(pad), uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
			uintptr(unsafe.Pointer(out)), uintptr(n), uintptr(unsafe.Pointer(got)), flags)
		runtime.KeepAlive(pad)
		runtime.KeepAlive(digest)
		return status("NCryptSignHash", r)
	}
	var n uint32
	if err := call(nil, 0, &n); err != nil {
		return nil, err
	}
	sig := make([]byte, n)
	if err := call(&sig[0], n, &n); err != nil {
		return nil, err
	}
	sig = sig[:n]
	if isRSA {
		return sig, nil
	}
	// CNG returns r||s; the server verifies ASN.1 DER.
	half := len(sig) / 2
	return asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(sig[:half]), new(big.Int).SetBytes(sig[half:])})
}

type winPlatform struct{}

func (winPlatform) machineID() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", fmt.Errorf("reading MachineGuid: %w", err)
	}
	defer k.Close()
	v, _, err := k.GetStringValue("MachineGuid")
	if err != nil || v == "" {
		return "", fmt.Errorf("reading MachineGuid: %v", err)
	}
	return v, nil
}

func (winPlatform) osName() string {
	v := windows.RtlGetVersion()
	return fmt.Sprintf("Windows %d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
}

func openMachineStore(name string) (windows.Handle, error) {
	p, _ := windows.UTF16PtrFromString(name)
	return windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM, 0, 0,
		windows.CERT_SYSTEM_STORE_LOCAL_MACHINE|windows.CERT_STORE_READONLY_FLAG, uintptr(unsafe.Pointer(p)))
}

type storeCert struct {
	ctx  *windows.CertContext
	cert *x509.Certificate
}

// readStore parses every certificate of a LocalMachine store; the contexts stay valid (duplicated).
func readStore(store windows.Handle) []storeCert {
	var out []storeCert
	var prev *windows.CertContext
	for {
		ctx, err := windows.CertEnumCertificatesInStore(store, prev)
		if err != nil || ctx == nil {
			return out
		}
		prev = ctx
		der := append([]byte(nil), unsafe.Slice(ctx.EncodedCert, ctx.Length)...)
		if c, err := x509.ParseCertificate(der); err == nil {
			out = append(out, storeCert{windows.CertDuplicateCertificateContext(ctx), c})
		}
	}
}

func hasClientAuth(c *x509.Certificate) bool {
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth || u == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func keyOK(c *x509.Certificate) bool {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen() >= 2048
	case *ecdsa.PublicKey:
		return k.Curve == elliptic.P256() || k.Curve == elliptic.P384()
	}
	return false
}

func (winPlatform) computerCert(issuer string) ([]string, crypto.Signer, error) {
	my, err := openMachineStore("MY")
	if err != nil {
		return nil, nil, fmt.Errorf("opening LocalMachine\\My: %w", err)
	}
	var cands []storeCert
	now := time.Now()
	for _, sc := range readStore(my) {
		c := sc.cert
		if bytes.Equal(c.RawSubject, c.RawIssuer) || !hasClientAuth(c) || !keyOK(c) ||
			now.Before(c.NotBefore) || now.After(c.NotAfter) || len(c.DNSNames) == 0 ||
			(issuer != "" && !strings.Contains(c.Issuer.String(), issuer)) {
			continue
		}
		cands = append(cands, sc)
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].cert.NotAfter.After(cands[j].cert.NotAfter) })
	for _, sc := range cands {
		var h windows.Handle
		var spec uint32
		var free bool
		if err := windows.CryptAcquireCertificatePrivateKey(sc.ctx,
			windows.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG|windows.CRYPT_ACQUIRE_SILENT_FLAG, nil, &h, &spec, &free); err != nil {
			continue // no private key, or not reachable
		}
		fmt.Fprintf(os.Stderr, "computer certificate: %s, issued by %s, serial %s\n",
			sc.cert.DNSNames[0], sc.cert.Issuer.String(), sc.cert.SerialNumber.Text(16))
		chain := []string{certPEM(sc.cert)}
		for _, ic := range intermediates(sc.cert) {
			chain = append(chain, certPEM(ic))
		}
		return chain, &cngSigner{uintptr(h), sc.cert.PublicKey}, nil
	}
	return nil, nil, errNoComputerOK
}

// intermediates walks up through LocalMachine\CA; the root is not sent (the tenant holds it).
func intermediates(leaf *x509.Certificate) []*x509.Certificate {
	store, err := openMachineStore("CA")
	if err != nil {
		return nil
	}
	pool := readStore(store)
	var out []*x509.Certificate
	cur := leaf
	for len(out) < 3 {
		var next *x509.Certificate
		for _, sc := range pool {
			c := sc.cert
			if c.IsCA && !bytes.Equal(c.RawSubject, c.RawIssuer) && bytes.Equal(c.RawSubject, cur.RawIssuer) && cur.CheckSignatureFrom(c) == nil {
				next = c
				break
			}
		}
		if next == nil {
			break
		}
		out = append(out, next)
		cur = next
	}
	return out
}

func certPEM(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

// hostKey opens the persisted machine key, creating an ECDSA P-256 key on first use.
func (winPlatform) hostKey() (crypto.Signer, error) {
	var prov uintptr
	name, _ := windows.UTF16PtrFromString(softwareKSP)
	r, _, _ := pOpenProvider.Call(uintptr(unsafe.Pointer(&prov)), uintptr(unsafe.Pointer(name)), 0)
	if err := status("NCryptOpenStorageProvider", r); err != nil {
		return nil, err
	}
	kn, _ := windows.UTF16PtrFromString(hostKeyName)
	var key uintptr
	r, _, _ = pOpenKey.Call(prov, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(kn)), 0, ncryptMachine)
	if r != 0 {
		if uint32(r) != nteBadKeyset && uint32(r) != nteNoKey {
			return nil, status("NCryptOpenKey", r)
		}
		alg, _ := windows.UTF16PtrFromString("ECDSA_P256")
		r, _, _ = pCreateKey.Call(prov, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(alg)), uintptr(unsafe.Pointer(kn)), 0, ncryptMachine)
		if err := status("NCryptCreatePersistedKey", r); err != nil {
			return nil, err
		}
		r, _, _ = pFinalizeKey.Call(key, 0)
		if err := status("NCryptFinalizeKey", r); err != nil {
			return nil, err
		}
	}
	blobType, _ := windows.UTF16PtrFromString("ECCPUBLICBLOB")
	blob := make([]byte, 8+64)
	var n uint32
	r, _, _ = pExportKey.Call(key, 0, uintptr(unsafe.Pointer(blobType)), 0, uintptr(unsafe.Pointer(&blob[0])), uintptr(len(blob)), uintptr(unsafe.Pointer(&n)), 0)
	if err := status("NCryptExportKey", r); err != nil {
		return nil, err
	}
	if n != 72 || binary.LittleEndian.Uint32(blob) != eccPublicP256 || binary.LittleEndian.Uint32(blob[4:]) != 32 {
		return nil, errors.New("host key is not an ECDSA P-256 key")
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(blob[8:40]), Y: new(big.Int).SetBytes(blob[40:72])}
	return &cngSigner{key, pub}, nil
}

func cmdEnrolHost(base string, args []string) error {
	return cmdHostEnrol(base, args, winPlatform{}, os.Stdout)
}
