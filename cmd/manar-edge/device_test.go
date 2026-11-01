package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
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
		"Restart=always", "WantedBy=multi-user.target",
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
