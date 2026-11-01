package jail

import (
	"net"
	"testing"
)

// A program that opens the proxy port by hand (not redirected) has no original destination, so the
// proxy drops it: nobody can use the proxy as an open relay.
func TestOrigDstFailsOnAConnectionThatWasNotRedirected(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go net.Dial("tcp", ln.Addr().String())
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := OrigDst(c); err == nil {
		t.Fatal("a connection that was not redirected has an original destination")
	}
}
