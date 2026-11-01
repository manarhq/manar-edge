package jail

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"gitlab.vax.sh/manar/manar-edge/internal/hostclient"
)

type fakePlatform struct {
	applied   []map[string]int
	teardowns int
	err       error
}

func (f *fakePlatform) Apply(p map[string]int) error {
	if f.err != nil {
		return f.err
	}
	cp := map[string]int{}
	for k, v := range p {
		cp[k] = v
	}
	f.applied = append(f.applied, cp)
	return nil
}
func (f *fakePlatform) Teardown() error { f.teardowns++; return nil }

func newRunner(f *fakePlatform) *runner {
	return &runner{pf: f, policy: NewPolicy(), asker: &fakeAsker{}, running: map[string]*toolProxy{}}
}

func cfg(status string, enabled bool, tools ...string) *hostclient.Config {
	return &hostclient.Config{Status: status, Jail: hostclient.JailConfig{Enabled: enabled, Tools: tools}}
}

func reachable(port int) bool {
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err == nil {
		c.Close()
	}
	return err == nil
}

func TestReconcileFollowsTheConfig(t *testing.T) {
	f := &fakePlatform{}
	r := newRunner(f)
	defer r.stop()

	// A device that is not approved, or JAIL switched off, filters nothing and installs nothing.
	r.reconcile(cfg("PENDING", true, claude))
	r.reconcile(cfg("APPROVED", false, claude))
	if len(f.applied) != 0 {
		t.Fatalf("applied %v", f.applied)
	}

	// Approved: the known tools get a proxy each; an unknown id is ignored.
	r.reconcile(cfg("APPROVED", true, claude, "host.codex-cli", "host.cursor", "bogus"))
	got := f.applied[len(f.applied)-1]
	if len(got) != 2 || got[claude] == 0 || got["host.codex-cli"] == 0 {
		t.Fatalf("ports %v", got)
	}
	port := got[claude]
	if !reachable(port) {
		t.Fatal("proxy not listening")
	}

	// The owner turns Protect off for one tool: its rules go first, then its proxy.
	r.reconcile(cfg("APPROVED", true, "host.codex-cli"))
	got = f.applied[len(f.applied)-1]
	if len(got) != 1 || got[claude] != 0 {
		t.Fatalf("ports %v", got)
	}
	if reachable(port) {
		t.Fatal("proxy of the released tool still listening")
	}

	// Everything off: empty set applied, nothing listening.
	r.reconcile(cfg("APPROVED", true))
	if got = f.applied[len(f.applied)-1]; len(got) != 0 {
		t.Fatalf("ports %v", got)
	}
	n := len(f.applied)
	r.reconcile(cfg("APPROVED", true)) // nothing wanted, nothing installed: no work
	if len(f.applied) != n {
		t.Fatal("applied again with nothing to do")
	}
}

func TestReconcileRemembersRules(t *testing.T) {
	r := newRunner(&fakePlatform{})
	defer r.stop()
	c := cfg("APPROVED", true, claude)
	c.Jail.Rules = []hostclient.JailRule{{ToolID: claude, Site: "ok.example", Mode: "ALLOW"}, {ToolID: claude, Site: "no.example", Mode: "DENY"}}
	r.reconcile(c)
	if v, _ := r.policy.Decide(claude, "ok.example"); v != Allow {
		t.Error("allow rule not applied")
	}
	if v, _ := r.policy.Decide(claude, "no.example"); v != Deny {
		t.Error("deny rule not applied")
	}
	c.Jail.Rules = nil // removed in the console
	r.reconcile(c)
	if v, _ := r.policy.Decide(claude, "ok.example"); v != Ask {
		t.Error("removed rule still applied")
	}
}

func TestAFailedApplyLeavesNothingBehind(t *testing.T) {
	f := &fakePlatform{err: errors.New("nft: boom")}
	r := newRunner(f)
	r.reconcile(cfg("APPROVED", true, claude))
	if f.teardowns == 0 {
		t.Fatal("a half-installed filter must be torn down")
	}
	if len(r.running) != 0 {
		t.Fatal("proxies left running for rules that are not there")
	}
}

func TestStopTearsDown(t *testing.T) {
	f := &fakePlatform{}
	r := newRunner(f)
	r.reconcile(cfg("APPROVED", true, claude))
	port := f.applied[0][claude]
	r.stop()
	if f.teardowns == 0 || reachable(port) {
		t.Fatal("stop must remove the rules and close the proxies")
	}
}
