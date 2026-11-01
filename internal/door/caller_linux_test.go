package door

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestCallerIsTheSocketOwnerFromTheKernelTable(t *testing.T) {
	var got string
	var ok bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok = callerOf(r)
		_, _ = io.WriteString(w, "x")
	}))
	defer srv.Close()
	res, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if !ok || got != fmt.Sprintf("uid:%d", os.Getuid()) {
		t.Fatalf("caller %q %v", got, ok)
	}
	if _, ok := tcpOwnerUID("/proc/net/tcp", "127.0.0.1:1"); ok {
		t.Fatal("a peer with no socket must be unknown")
	}
	if _, ok := tcpOwnerUID("/proc/net/tcp", "[::1]:5"); ok {
		t.Fatal("IPv6 peers are not served")
	}
}
