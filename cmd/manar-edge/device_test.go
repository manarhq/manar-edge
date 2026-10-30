package main

import (
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
