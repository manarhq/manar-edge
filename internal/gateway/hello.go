package gateway

import "io"

// PeekHello reads a TLS ClientHello from r without answering it. sni is the server_name the client
// asked for (empty if none), ech says the hello carries encrypted_client_hello (then sni is only a
// cover name) and raw is every byte consumed, to be replayed to the real server. The on-device JAIL
// proxy (internal/jail) uses it as the gateway's own proxy does.
func PeekHello(r io.Reader) (sni string, ech bool, raw []byte, err error) {
	h, err := peekHello(r)
	return h.sni, h.ech, h.raw, err
}
