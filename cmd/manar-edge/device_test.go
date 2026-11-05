package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manarhq/manar-edge/internal/hostclient"
)

func TestHashedMachineIDIsStableAndAcceptedByTheAPI(t *testing.T) {
	a, b := hashedMachineID("abc\n"), hashedMachineID("abc")
	if a != b {
		t.Fatal("not stable")
	}
	if !machineIDPattern.MatchString(a) || strings.Contains(a, "abc") {
		t.Fatalf("id = %q", a)
	}
	if hashedMachineID("abd") == a {
		t.Fatal("collision")
	}
}

func TestUnitTextRunsTheServiceFromTheStateDir(t *testing.T) {
	u := unitText("/usr/local/bin/manar-edge", "/var/lib/manar-edge")
	for _, want := range []string{
		"ExecStart=/usr/local/bin/manar-edge --state-dir /var/lib/manar-edge service run",
		"EnvironmentFile=-/var/lib/manar-edge/proxy.env", "Restart=always", "WantedBy=multi-user.target",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q:\n%s", want, u)
		}
	}
}

func TestInstallNeedsACode(t *testing.T) {
	if err := cmdInstall(t.TempDir(), nil, io.Discard); err == nil || !strings.Contains(err.Error(), "--code") {
		t.Fatalf("err = %v", err)
	}
}

func TestServiceNeedsASubcommand(t *testing.T) {
	if err := cmdService(t.TempDir(), []string{"bogus"}); err == nil {
		t.Fatal("want an error")
	}
}

func TestUninstallTakesDownEveryAgentThenTheBinaryLast(t *testing.T) {
	var order []string
	st := uninstallSteps{
		removeService: func() error { order = append(order, "service"); return nil },
		cleanup:       func(context.Context) []error { order = append(order, "cleanup"); return nil },
		agents:        func() []string { return []string{"a-1", "b-2"} },
		down:          func(a string) error { order = append(order, "down "+a); return nil },
		claudeCode:    func() error { order = append(order, "claude"); return nil },
		removeHost:    func() error { order = append(order, "host"); return nil },
		removeBinary:  func() error { order = append(order, "binary"); return nil },
	}
	if errs := runUninstall(context.Background(), st, io.Discard); len(errs) != 0 {
		t.Fatal(errs)
	}
	want := "service,cleanup,down a-1,down b-2,claude,host,binary"
	if got := strings.Join(order, ","); got != want {
		t.Fatalf("order = %s", got)
	}
}

func TestUninstallKeepsTheBinaryWhenAnAgentWontComeDown(t *testing.T) {
	removed := false
	st := uninstallSteps{
		removeService: func() error { return nil },
		cleanup:       func(context.Context) []error { return nil },
		agents:        func() []string { return []string{"a-1"} },
		down:          func(string) error { return errors.New("process still running") },
		claudeCode:    func() error { return nil },
		removeHost:    func() error { return nil },
		removeBinary:  func() error { removed = true; return nil },
	}
	errs := runUninstall(context.Background(), st, io.Discard)
	if len(errs) != 1 || removed {
		t.Fatalf("errs=%v removed=%v", errs, removed)
	}
}

func TestRemoveClaudeSettingsUndoesOnlyWhatManarWrote(t *testing.T) {
	// Manar's policy plus a hook and a setting of the user's own.
	base := []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"mine"}]}]},"model":"x"}`)
	with, err := claudeSettings(base, "/usr/local/bin/manar-edge", "me-agent")
	if err != nil {
		t.Fatal(err)
	}
	out, changed, empty, err := removeClaudeSettings(with)
	if err != nil || !changed || empty {
		t.Fatalf("changed=%v empty=%v err=%v", changed, empty, err)
	}
	s := string(out)
	for _, gone := range []string{"manar-edge", "allowManagedHooksOnly", "dontAsk", "ANTHROPIC_BASE_URL", "requiredMinimumVersion"} {
		if strings.Contains(s, gone) {
			t.Errorf("%q is still there:\n%s", gone, s)
		}
	}
	for _, kept := range []string{`"mine"`, `"model"`} {
		if !strings.Contains(s, kept) {
			t.Errorf("%q was removed:\n%s", kept, s)
		}
	}
	// A file made only by Manar goes away entirely.
	only, _ := claudeSettings(nil, "/usr/local/bin/manar-edge", "me-agent")
	if _, changed, empty, _ := removeClaudeSettings(only); !changed || !empty {
		t.Fatalf("changed=%v empty=%v", changed, empty)
	}
	// A file without Manar's hook is not touched.
	if _, changed, _, _ := removeClaudeSettings([]byte(`{"model":"x"}`)); changed {
		t.Fatal("touched a file that is not ours")
	}
}

func TestUninstallRestoresSecretsFirstAndStopsIfItCannot(t *testing.T) {
	var order []string
	st := uninstallSteps{
		restoreSecrets: func() error { order = append(order, "restore"); return nil },
		removeService:  func() error { order = append(order, "service"); return nil },
		cleanup:        func(context.Context) []error { order = append(order, "cleanup"); return nil },
		agents:         func() []string { return nil },
		claudeCode:     func() error { return nil },
		removeHost:     func() error { return nil },
		removeBinary:   func() error { return nil },
	}
	if errs := runUninstall(context.Background(), st, io.Discard); len(errs) != 0 {
		t.Fatal(errs)
	}
	if got := strings.Join(order, ","); got != "restore,service,cleanup" {
		t.Fatalf("order = %s", got)
	}

	order = nil
	st.restoreSecrets = func() error { order = append(order, "restore"); return errors.New("key file in the way") }
	var out strings.Builder
	errs := runUninstall(context.Background(), st, &out)
	if len(errs) != 1 || strings.Join(order, ",") != "restore" {
		t.Fatalf("a failed restore must stop everything: errs=%v order=%v", errs, order)
	}
	if !strings.Contains(out.String(), "manar-edge secret restore --all") {
		t.Fatalf("the message must name a command that exists:\n%s", out.String())
	}
}

func TestInstallTakesTheCodeFromTheEnvironment(t *testing.T) {
	t.Setenv(installCodeEnv, "ABCDEFGH23")
	err := cmdInstall(t.TempDir(), []string{"--tenant", "me-1", "--api", "https://127.0.0.1:1", "--host-url", "https://127.0.0.1:1"}, io.Discard)
	if err == nil || strings.Contains(err.Error(), "usage") {
		t.Fatalf("the code in the environment was not used: %v", err)
	}
	if _, set := os.LookupEnv(installCodeEnv); set {
		t.Fatal("the code is still in the environment for child processes")
	}
}

// One laptop, two workspaces: the person is asked in plain words, and only "y" or "yes" moves it.
func TestMoveQuestionNeedsAnExplicitYes(t *testing.T) {
	e := &hostclient.OtherWorkspaceError{From: "acme", To: "globex"}
	for in, want := range map[string]bool{"y\n": true, "YES\n": true, "\n": false, "n\n": false, "": false, "sure\n": false} {
		var out strings.Builder
		if got := askMove(e, strings.NewReader(in), &out); got != want {
			t.Errorf("%q: got %v", in, got)
		}
		if !strings.Contains(out.String(), `moves from "acme" to "globex"`) || !strings.Contains(out.String(), "rules will apply") {
			t.Fatalf("question: %s", out.String())
		}
	}
	msg := moveRefused(e).Error()
	for _, want := range []string{"--confirm-move", "MANAR_CONFIRM_MOVE=1", `"acme"`, `"globex"`} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal lacks %q: %s", want, msg)
		}
	}
}

func TestKeylessEnrolRefusesAComputerOfAnotherWorkspace(t *testing.T) {
	base := t.TempDir()
	if err := refuseOtherWorkspace(base, "acme"); err != nil {
		t.Fatalf("not enrolled: %v", err)
	}
	_ = os.MkdirAll(base+"/host", 0o700)
	_ = os.WriteFile(base+"/host/host.json", []byte(`{"tenantSlug":"personal-1"}`), 0o600)
	if err := refuseOtherWorkspace(base, "personal-1"); err != nil {
		t.Fatalf("same workspace: %v", err)
	}
	if err := refuseOtherWorkspace(base, "acme"); err == nil || !strings.Contains(err.Error(), "personal-1") {
		t.Fatalf("err = %v", err)
	}
	_ = hostclient.MarkRemoved(base)
	if err := refuseOtherWorkspace(base, "acme"); err != nil {
		t.Fatalf("a removed enrolment must not block: %v", err)
	}
}

// hostclient.New (and with it the proxy variables it reads) runs only in the device service, which
// JAIL never configures: JAIL's HTTPS_PROXY goes to a protected tool's settings and child
// processes (cmd.Env), never into this process. This fails if either stops being true.
func TestTheDeviceClientIsBuiltOnlyInTheServiceAndNoCodeSetsProxyVariablesForItself(t *testing.T) {
	var newCalls []string
	err := filepath.WalkDir("../..", func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, _ := os.ReadFile(p)
		src := string(b)
		if strings.Contains(src, "hostclient.New(") {
			newCalls = append(newCalls, filepath.ToSlash(p))
		}
		for _, call := range []string{"os.Setenv(", "os.Unsetenv(", "os.Clearenv("} {
			for _, at := range strings.Split(src, call)[1:] {
				if line, _, _ := strings.Cut(at, "\n"); strings.Contains(strings.ToUpper(line), "PROXY") {
					t.Errorf("%s sets a proxy variable for the process itself: %s%s", p, call, line)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(newCalls) != 1 || newCalls[0] != "../../cmd/manar-edge/device.go" {
		t.Fatalf("hostclient.New is called from %v, want only device.go (serveDevice)", newCalls)
	}
}
