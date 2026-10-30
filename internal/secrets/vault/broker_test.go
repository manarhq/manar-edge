package vault

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

type fakeApprover struct {
	answers []Decision
	err     error
	asked   int
}

func (f *fakeApprover) Ask(context.Context, Request) (Decision, error) {
	f.asked++
	if f.err != nil {
		return "", f.err
	}
	d := f.answers[0]
	if len(f.answers) > 1 {
		f.answers = f.answers[1:]
	}
	return d, nil
}

func brokerFor(t *testing.T, a Approver) (*Broker, *time.Time) {
	e := newEnv(t, credsFile, 0o600)
	if _, err := e.v.StoreAWS("default"); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	req.Owner = e.owner
	return &Broker{V: e.v, A: a, Now: func() time.Time { return now }}, &now
}

var req = Request{Kind: "aws", Ref: "default", Program: "/usr/bin/aws", SHA: "aa11"}

func TestBrokerGrantScopes(t *testing.T) {
	ap := &fakeApprover{answers: []Decision{AllowOnce}}
	b, now := brokerFor(t, ap)
	for i := 0; i < 2; i++ {
		if out, err := b.Credential(context.Background(), req); err != nil || !strings.Contains(string(out), "secretOne") {
			t.Fatalf("%v %s", err, out)
		}
	}
	if ap.asked != 2 {
		t.Fatalf("allow once must ask every time, asked %d", ap.asked)
	}

	ap.asked, ap.answers = 0, []Decision{Allow8h}
	_, _ = b.Credential(context.Background(), req)
	_, _ = b.Credential(context.Background(), req)
	if ap.asked != 1 {
		t.Fatalf("8h grant not reused: %d", ap.asked)
	}
	*now = now.Add(9 * time.Hour)
	_, _ = b.Credential(context.Background(), req)
	if ap.asked != 2 {
		t.Fatal("8h grant did not expire")
	}

	ap.asked, ap.answers = 0, []Decision{AllowAlways}
	other := req
	other.Program, other.SHA = "/usr/bin/terraform", "bb22"
	_, _ = b.Credential(context.Background(), other)
	*now = now.Add(1000 * time.Hour)
	_, _ = b.Credential(context.Background(), other)
	if ap.asked != 1 {
		t.Fatal("always grant not kept")
	}
	// A grant for one program is not a grant for another.
	ap.answers = []Decision{Deny}
	if _, err := b.Credential(context.Background(), Request{Kind: "aws", Ref: "default", Owner: req.Owner, Program: "/tmp/evil", SHA: "cc33"}); err == nil {
		t.Fatal("another program inherited a grant")
	}
}

func TestBrokerDeniesOnDenyErrorAndUnknownAnswers(t *testing.T) {
	for name, ap := range map[string]*fakeApprover{
		"deny":    {answers: []Decision{Deny}},
		"error":   {err: errors.New("console unreachable")},
		"garbage": {answers: []Decision{"MAYBE"}},
	} {
		b, _ := brokerFor(t, ap)
		denied := 0
		b.OnDenied = func(Request) { denied++ }
		if out, err := b.Credential(context.Background(), req); err == nil || strings.Contains(string(out), "secret") || denied != 1 {
			t.Fatalf("%s: err=%v denied=%d out=%q", name, err, denied, out)
		}
	}
}

func TestBrokerNeverKeepsAStandingGrantForAnUnidentifiedProgram(t *testing.T) {
	ap := &fakeApprover{answers: []Decision{AllowAlways}}
	b, _ := brokerFor(t, ap)
	r := req
	r.Program, r.SHA = "", ""
	_, _ = b.Credential(context.Background(), r)
	_, _ = b.Credential(context.Background(), r)
	if ap.asked != 2 {
		t.Fatal("an unidentified program got a standing grant")
	}
}

func TestHelperProtocolThroughHandleConn(t *testing.T) {
	ap := &fakeApprover{answers: []Decision{AllowOnce}}
	b, _ := brokerFor(t, ap)
	env := Env{Identify: func(pid int) (Program, error) { return Program{Path: "/usr/bin/aws", SHA: "aa11"}, nil }}
	srv, cli := net.Pipe()
	go func() {
		defer srv.Close()
		handleConn(context.Background(), srv, Peer{PID: 4321, Owner: req.Owner}, b, env)
	}()
	data, err := ask(cli, ipcRequest{Kind: "aws", Ref: "default"})
	if err != nil || !strings.Contains(string(data), "AKIAEXAMPLE1") {
		t.Fatalf("%v %s", err, data)
	}
	cli.Close()

	srv2, cli2 := net.Pipe()
	go func() {
		defer srv2.Close()
		handleConn(context.Background(), srv2, Peer{PID: 1, Owner: req.Owner}, b, env)
	}()
	if _, err := ask(cli2, ipcRequest{Kind: "aws", Ref: "../../etc/passwd"}); err == nil {
		t.Fatal("a bad profile name must be refused")
	}
}

// Bob must not get Alice's keys, whatever he asks and whatever Alice allowed.
func TestAnotherUserNeverGetsTheSecret(t *testing.T) {
	ap := &fakeApprover{answers: []Decision{AllowAlways}}
	b, _ := brokerFor(t, ap)
	if _, err := b.Credential(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	bob := req
	bob.Owner = "u4242"
	asked := ap.asked
	if out, err := b.Credential(context.Background(), bob); err == nil || strings.Contains(string(out), "secret") {
		t.Fatalf("bob got alice's keys: %v %q", err, out)
	}
	if ap.asked != asked {
		t.Fatal("bob's request must be refused before anyone is asked")
	}
}

func TestAGrantIsBoundToTheBinaryHash(t *testing.T) {
	ap := &fakeApprover{answers: []Decision{AllowAlways}}
	b, _ := brokerFor(t, ap)
	_, _ = b.Credential(context.Background(), req)
	changed := req
	changed.SHA = "ff99" // same path, replaced binary
	_, _ = b.Credential(context.Background(), changed)
	if ap.asked != 2 {
		t.Fatalf("a replaced binary reused the old grant (asked %d)", ap.asked)
	}
}

type gateApprover struct {
	started chan string
	release chan Decision
}

func (g *gateApprover) Ask(_ context.Context, r Request) (Decision, error) {
	g.started <- r.Program
	return <-g.release, nil
}

func TestAPromptDoesNotBlockOtherPrograms(t *testing.T) {
	g := &gateApprover{started: make(chan string, 2), release: make(chan Decision, 2)}
	b, _ := brokerFor(t, g)
	other := req
	other.Program, other.SHA = "/usr/bin/terraform", "bb22"
	done := make(chan error, 2)
	go func() { _, err := b.Credential(context.Background(), req); done <- err }()
	<-g.started
	go func() { _, err := b.Credential(context.Background(), other); done <- err }()
	select {
	case <-g.started: // the second program is asked while the first still waits
	case <-time.After(2 * time.Second):
		t.Fatal("the second prompt waited behind the first")
	}
	g.release <- AllowOnce
	g.release <- Deny
	<-done
	<-done
}

func TestRestoreAllOnlyForAdministrators(t *testing.T) {
	ap := &fakeApprover{answers: []Decision{Deny}}
	b, _ := brokerFor(t, ap)
	called := 0
	env := Env{RestoreAll: func() error { called++; return nil }}
	for _, admin := range []bool{false, true} {
		want := map[bool]int{false: 0, true: 1}[admin]
		srv, cli := net.Pipe()
		go func() {
			defer srv.Close()
			handleConn(context.Background(), srv, Peer{PID: 1, Owner: "u1", Admin: admin}, b, env)
		}()
		_, err := ask(cli, ipcRequest{Op: "restore-all"})
		cli.Close()
		if (err == nil) != admin || called != want {
			t.Fatalf("admin=%v err=%v called=%d", admin, err, called)
		}
	}
}
