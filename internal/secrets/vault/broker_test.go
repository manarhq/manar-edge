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
	return &Broker{V: e.v, A: a, Now: func() time.Time { return now }}, &now
}

var req = Request{Kind: "aws", Ref: "default", Program: "/usr/bin/aws"}

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
	other.Program = "/usr/bin/terraform"
	_, _ = b.Credential(context.Background(), other)
	*now = now.Add(1000 * time.Hour)
	_, _ = b.Credential(context.Background(), other)
	if ap.asked != 1 {
		t.Fatal("always grant not kept")
	}
	// A grant for one program is not a grant for another.
	ap.answers = []Decision{Deny}
	if _, err := b.Credential(context.Background(), Request{Kind: "aws", Ref: "default", Program: "/tmp/evil"}); err == nil {
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
	r.Program = ""
	_, _ = b.Credential(context.Background(), r)
	_, _ = b.Credential(context.Background(), r)
	if ap.asked != 2 {
		t.Fatal("an unidentified program got a standing grant")
	}
}

func TestHelperProtocolThroughHandleConn(t *testing.T) {
	ap := &fakeApprover{answers: []Decision{AllowOnce}}
	b, _ := brokerFor(t, ap)
	srv, cli := net.Pipe()
	var gotPID int
	go func() {
		defer srv.Close()
		handleConn(context.Background(), srv, 4321, b, func(pid int) string { gotPID = pid; return "/usr/bin/aws" })
	}()
	data, err := askDaemon(cli, "aws", "default")
	if err != nil || !strings.Contains(string(data), "AKIAEXAMPLE1") || gotPID != 4321 {
		t.Fatalf("%v %s pid=%d", err, data, gotPID)
	}
	cli.Close()

	srv2, cli2 := net.Pipe()
	go func() {
		defer srv2.Close()
		handleConn(context.Background(), srv2, 1, b, func(int) string { return "" })
	}()
	if _, err := askDaemon(cli2, "aws", "../../etc/passwd"); err == nil {
		t.Fatal("a bad profile name must be refused")
	}
}
