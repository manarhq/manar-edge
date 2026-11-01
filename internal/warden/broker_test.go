package warden

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

// fakeConn lets a test say who the peer is.
type fakeConn struct {
	net.Conn
	uid uint32
}

type fakeListener struct {
	ch chan net.Conn
}

func (l fakeListener) Accept() (net.Conn, error) {
	c, ok := <-l.ch
	if !ok {
		return nil, net.ErrClosed
	}
	return c, nil
}
func (l fakeListener) Close() error   { close(l.ch); return nil }
func (l fakeListener) Addr() net.Addr { return &net.UnixAddr{} }

func uidCheck(allowed ...uint32) PeerCheck {
	return func(c net.Conn) (string, error) {
		fc := c.(fakeConn)
		return fmt.Sprintf("uid-%d", fc.uid), CheckUID(fc.uid, allowed)
	}
}

func connect(t *testing.T, l fakeListener, uid uint32) net.Conn {
	t.Helper()
	server, client := net.Pipe()
	l.ch <- fakeConn{Conn: server, uid: uid}
	return client
}

// Set once: brokers from earlier cases still read it from their goroutines.
func init() { writeTimeout = 100 * time.Millisecond }

func serve(t *testing.T, check PeerCheck) (*Broker, fakeListener) {
	t.Helper()
	b := NewBroker(check)
	l := fakeListener{ch: make(chan net.Conn)}
	go b.Serve(l)
	t.Cleanup(func() { defer func() { _ = recover() }(); l.Close() })
	return b, l
}

func waitHelper(t *testing.T, b *Broker, want bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if b.HasHelper() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("HasHelper stayed %v", !want)
}

func TestBrokerRejectsOtherUsers(t *testing.T) {
	b, l := serve(t, uidCheck(1000))
	other := connect(t, l, 1001)
	defer other.Close()
	// The broker closes a refused connection: the read ends.
	_ = other.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := other.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected the refused connection to be closed")
	}
	if b.HasHelper() {
		t.Fatal("a refused user became a helper")
	}
	if _, err := b.Ask(context.Background(), Prompt{ID: "x"}); !errors.Is(err, ErrNoHelper) {
		t.Fatalf("Ask with no helper = %v, want ErrNoHelper", err)
	}
}

func TestCheckUIDAllowsRootAndListed(t *testing.T) {
	if CheckUID(0, nil) != nil {
		t.Fatal("root must be allowed")
	}
	if CheckUID(1000, []uint32{1000}) != nil {
		t.Fatal("listed uid must be allowed")
	}
	if CheckUID(1001, []uint32{1000}) == nil {
		t.Fatal("unlisted uid must be refused")
	}
	if CheckUID(1001, nil) == nil {
		t.Fatal("an empty allow list lets only root in")
	}
}

func TestBrokerAskReturnsTheUsersAnswer(t *testing.T) {
	b, l := serve(t, uidCheck(1000))
	client := connect(t, l, 1000)
	defer client.Close()
	waitHelper(t, b, true)
	hc := newCodec(client)

	go func() {
		m, err := hc.recv()
		if err != nil || m.Type != "prompt" {
			return
		}
		_ = hc.send(msg{Type: "answer", ID: m.Prompt.ID, Decision: ApproveEight})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	d, err := b.Ask(ctx, Prompt{ID: "p1", Kind: KindAction, ToolID: "host.cursor", ActionID: "file.read", Resource: "~/.aws/credentials"})
	if err != nil || d != ApproveEight {
		t.Fatalf("Ask = %q, %v", d, err)
	}
}

func TestBrokerIgnoresInvalidDecisionsAndTimesOut(t *testing.T) {
	b, l := serve(t, uidCheck(1000))
	client := connect(t, l, 1000)
	defer client.Close()
	waitHelper(t, b, true)
	hc := newCodec(client)
	go func() {
		m, _ := hc.recv()
		// "approve_forever" is not a decision; with one helper it counts as a closed prompt.
		_ = hc.send(msg{Type: "answer", ID: m.Prompt.ID, Decision: "approve_forever"})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	d, err := b.Ask(ctx, Prompt{ID: "p2"})
	if err != nil || d != Dismissed {
		t.Fatalf("Ask = %q, %v; want Dismissed", d, err)
	}
}

func TestPipeUserCannotCreatePipeInstances(t *testing.T) {
	// FILE_CREATE_PIPE_INSTANCE is 0x4 (same bit as FILE_APPEND_DATA); it must not be granted.
	var mask uint32
	if _, err := fmt.Sscanf(pipeUserRights, "0x%x", &mask); err != nil {
		t.Fatal(err)
	}
	if mask&0x4 != 0 {
		t.Fatalf("user rights %s include FILE_CREATE_PIPE_INSTANCE", pipeUserRights)
	}
	// but connecting still needs read, write data and synchronize
	for _, bit := range []uint32{0x1, 0x2, 0x100000} {
		if mask&bit == 0 {
			t.Fatalf("user rights %s miss %#x", pipeUserRights, bit)
		}
	}
}

func TestPipeSDDLAllowsOnlySystemAndOneSID(t *testing.T) {
	got, err := PipeSDDL("S-1-5-21-1004336348-1177238915-682003330-1001")
	want := "D:P(A;;GA;;;SY)(A;;0x12019b;;;S-1-5-21-1004336348-1177238915-682003330-1001)"
	if err != nil || got != want {
		t.Fatalf("PipeSDDL = %q, %v", got, err)
	}
	for _, bad := range []string{"", "WD", "S-1-1-0)(A;;GA;;;WD", "S-1-5-21-1 ", "S-1-"} {
		if _, err := PipeSDDL(bad); err == nil {
			t.Errorf("PipeSDDL(%q) accepted", bad)
		}
	}
}

func TestOnlyOneHelperPerSession(t *testing.T) {
	b, l := serve(t, uidCheck(1000))
	first := connect(t, l, 1000)
	defer first.Close()
	waitHelper(t, b, true)
	second := connect(t, l, 1000)
	defer second.Close()
	// The second connection is closed by the broker; the first stays the helper.
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("a second helper for the same session was kept")
	}
	if !b.HasHelper() {
		t.Fatal("the first helper was dropped")
	}
}
