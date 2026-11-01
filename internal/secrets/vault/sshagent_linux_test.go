//go:build linux

package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type answers struct {
	d     atomic.Value // Decision
	calls atomic.Int32
}

func (a *answers) Ask(context.Context, Request) (Decision, error) {
	a.calls.Add(1)
	return a.d.Load().(Decision), nil
}

type rig struct {
	t                    *testing.T
	home                 string
	key                  string
	keyRaw               []byte
	pub                  ssh.PublicKey
	v                    *Vault
	srv                  *AgentServer
	ans                  *answers
	owner                string
	uid                  int
	profile, profileOrig []byte
}

func newRig(t *testing.T) *rig {
	t.Helper()
	root, err := os.MkdirTemp("", "mv")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	home := filepath.Join(root, "home")
	_ = os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	pubk, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatal(err)
	}
	raw := pem.EncodeToMemory(blk)
	key := filepath.Join(home, ".ssh", "id_test")
	if err := os.WriteFile(key, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	profile := []byte("export A=1\necho no newline at the end") // deliberately no trailing newline
	if err := os.WriteFile(filepath.Join(home, ".profile"), profile, 0o644); err != nil {
		t.Fatal(err)
	}
	pk, _ := ssh.NewPublicKey(pubk)
	oldSock := AgentSocket
	AgentSocket = func(uid int) string { return filepath.Join(root, "s"+strconv.Itoa(uid)+".sock") }
	t.Cleanup(func() { AgentSocket = oldSock; SetAIChain(nil) })
	v := &Vault{Store: FileStore{Dir: filepath.Join(root, "state", "vault")}, Homes: func() []string { return []string{home} }, Keys: NewKeyring()}
	w, err := WhoOfHome(home)
	if err != nil {
		t.Fatal(err)
	}
	ans := &answers{}
	ans.d.Store(Deny)
	b := &Broker{V: v, A: ans}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := &AgentServer{V: v, B: b, Ctx: ctx}
	t.Cleanup(srv.Close)
	return &rig{t: t, home: home, key: key, keyRaw: raw, pub: pk, v: v, srv: srv, ans: ans, owner: w.Key(), uid: w.UID,
		profile: profile, profileOrig: profile}
}

func (r *rig) client() agent.ExtendedAgent {
	r.t.Helper()
	c, err := net.DialTimeout("unix", AgentSocket(r.uid), 2*time.Second)
	if err != nil {
		r.t.Fatalf("agent socket: %v", err)
	}
	r.t.Cleanup(func() { c.Close() })
	return agent.NewClient(c).(agent.ExtendedAgent)
}

func (r *rig) move() {
	r.t.Helper()
	if _, err := r.v.StoreSSHFor(r.owner, "id_test"); err != nil {
		r.t.Fatal(err)
	}
	r.srv.Ensure()
}

func TestMoveSignAskDenyRestoreByteIdentical(t *testing.T) {
	r := newRig(t)
	r.move()

	if _, err := os.Stat(r.key); !os.IsNotExist(err) {
		t.Fatal("the key file must be gone after the move")
	}
	if p, _ := os.ReadFile(filepath.Join(r.home, ".profile")); !bytes.Contains(p, []byte(blockBegin)) || !bytes.HasPrefix(p, r.profileOrig) {
		t.Fatal("the shell snippet is added after the user's own lines")
	}
	data := []byte("challenge")

	// The person's own terminal (no AI tool above the caller): signs without a question.
	SetAIChain(func(int) (int, bool) { return 0, false })
	c := r.client()
	keys, err := c.List()
	if err != nil || len(keys) != 1 || keys[0].Comment != "manar:id_test" {
		t.Fatalf("list: %v %v", keys, err)
	}
	sig, err := c.Sign(r.pub, data)
	if err != nil || r.pub.Verify(data, sig) != nil {
		t.Fatalf("the person's own ssh must sign: %v", err)
	}
	if r.ans.calls.Load() != 0 {
		t.Fatal("the person's own program is never asked")
	}

	if p, err := exec.LookPath("ssh-add"); err == nil { // the real client talks to it too
		cmd := exec.Command(p, "-l")
		cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+AgentSocket(r.uid))
		if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), ssh.FingerprintSHA256(r.pub)) {
			t.Fatalf("ssh-add -l: %v %s", err, out)
		}
	}

	// An AI tool's chain: denied when the person says no (or does not answer)...
	SetAIChain(func(int) (int, bool) { return os.Getpid(), true })
	if _, err := r.client().Sign(r.pub, data); err == nil {
		t.Fatal("an AI tool must not sign without a yes")
	}
	// ... signs after a yes.
	r.ans.d.Store(AllowOnce)
	sig, err = r.client().Sign(r.pub, data)
	if err != nil || r.pub.Verify(data, sig) != nil {
		t.Fatalf("allowed program must sign: %v", err)
	}
	// "Always" is remembered for that exact binary and user: no second question.
	r.ans.d.Store(AllowAlways)
	_, _ = r.client().Sign(r.pub, data)
	n := r.ans.calls.Load()
	if _, err := r.client().Sign(r.pub, data); err != nil || r.ans.calls.Load() != n {
		t.Fatalf("a standing grant must not ask again: %v", err)
	}

	// Restore: key file byte-identical with its mode, profile byte-identical, agent gone.
	if err := r.v.RestoreSSHFor(r.owner, "id_test"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(r.key)
	st, _ := os.Stat(r.key)
	if !bytes.Equal(got, r.keyRaw) || st.Mode().Perm() != 0o600 {
		t.Fatal("restored key differs from the original")
	}
	if p, _ := os.ReadFile(filepath.Join(r.home, ".profile")); !bytes.Equal(p, r.profileOrig) {
		t.Fatalf("profile not restored byte for byte: %q", p)
	}
	r.srv.Ensure()
	if _, err := os.Stat(AgentSocket(r.uid)); !os.IsNotExist(err) {
		t.Fatal("the socket must go when the last key is back")
	}
}

func TestAgentKilledIsRestartedByTheService(t *testing.T) {
	r := newRig(t)
	r.move()
	SetAIChain(func(int) (int, bool) { return 0, false })
	r.srv.mu.Lock()
	al := r.srv.ls[r.uid]
	r.srv.mu.Unlock()
	al.l.Close() // the accept loop dies
	<-al.done
	r.srv.Ensure()
	if _, err := r.client().Sign(r.pub, []byte("x")); err != nil {
		t.Fatalf("after the restart: %v", err)
	}
	_ = os.Remove(AgentSocket(r.uid)) // socket file deleted under it
	r.srv.Ensure()
	if _, err := r.client().Sign(r.pub, []byte("x")); err != nil {
		t.Fatalf("after the socket was removed: %v", err)
	}
}

func TestUninstallRestoresEveryKey(t *testing.T) {
	r := newRig(t)
	r.move()
	if err := r.v.RestoreAll(); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(r.key); !bytes.Equal(got, r.keyRaw) {
		t.Fatal("uninstall must bring the key back")
	}
	if es, _ := r.v.Entries(); len(es) != 0 {
		t.Fatal("vault not empty")
	}
}

// The vault folder alone holds nothing readable.
func TestVaultIsEncryptedAtRest(t *testing.T) {
	r := newRig(t)
	r.move()
	dir := r.v.Store.(FileStore).Dir
	ents, _ := os.ReadDir(dir)
	if len(ents) == 0 {
		t.Fatal("empty vault")
	}
	for _, e := range ents {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		if bytes.Contains(b, []byte("OPENSSH PRIVATE KEY")) || bytes.Contains(b, r.keyRaw[:40]) {
			t.Fatalf("%s holds the key in clear", e.Name())
		}
	}
	st, err := os.Stat(filepath.Join(filepath.Dir(dir), "vault.key"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("vault.key: %v %v", st, err)
	}
}

func TestPassphraseKeyAndOtherUsersSocketAreRefused(t *testing.T) {
	r := newRig(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, _ := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("pw"))
	enc := filepath.Join(r.home, ".ssh", "id_enc")
	_ = os.WriteFile(enc, pem.EncodeToMemory(blk), 0o600)
	if _, err := r.v.StoreSSHFor(r.owner, "id_enc"); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Fatalf("a key with a passphrase stays where it is: %v", err)
	}
	if _, err := os.Stat(enc); err != nil {
		t.Fatal("the file must still be there")
	}
	if _, err := r.v.StoreSSHFor("u99999", "id_test"); err == nil {
		t.Fatal("another user's name must not match this home")
	}
	if names := r.v.DetectSSH(); len(names) != 1 || names[0] != "id_test" {
		t.Fatalf("detect offers the movable key only: %v", names)
	}
}

// A failure while setting up leaves the key where it was.
func TestFailureBeforeRemovalKeepsTheKey(t *testing.T) {
	r := newRig(t)
	_ = os.Chmod(filepath.Join(r.home, ".profile"), 0o444)
	_ = os.Chmod(r.home, 0o555) // profile cannot be rewritten (rename into the folder fails)
	defer os.Chmod(r.home, 0o755)
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	if _, err := r.v.StoreSSHFor(r.owner, "id_test"); err == nil {
		t.Fatal("expected a failure")
	}
	if got, err := os.ReadFile(r.key); err != nil || !bytes.Equal(got, r.keyRaw) {
		t.Fatal("the key file must be untouched")
	}
	if es, _ := r.v.Entries(); len(es) != 0 || len(r.v.Keys.For(r.owner)) != 0 {
		t.Fatal("nothing may be left in the vault or the agent")
	}
}

// bufRW is an in-memory connection for handleConn.
type bufRW struct{ in, out bytes.Buffer }

func (b *bufRW) Read(p []byte) (int, error)  { return b.in.Read(p) }
func (b *bufRW) Write(p []byte) (int, error) { return b.out.Write(p) }

func TestRestoreFromAnAIToolIsAQuestion(t *testing.T) {
	r := newRig(t)
	r.move()
	restored := 0
	env := Env{RestoreSSH: func(owner, name string) error { restored++; return nil }}
	b := &Broker{V: r.v, A: r.ans}
	call := func() string {
		c := &bufRW{}
		c.in.WriteString(`{"op":"ssh-restore","ref":""}` + "\n")
		handleConn(context.Background(), c, Peer{PID: os.Getpid(), Owner: r.owner}, b, env)
		return c.out.String()
	}
	// The person at a terminal: no question.
	SetAIChain(func(int) (int, bool) { return 0, false })
	if out := call(); !strings.Contains(out, `"ok":true`) || restored != 1 || r.ans.calls.Load() != 0 {
		t.Fatalf("human restore: %s restored=%d", out, restored)
	}
	// An AI tool's chain: refused when the person says no, done after a yes, and never remembered.
	SetAIChain(func(int) (int, bool) { return os.Getpid(), true })
	r.ans.d.Store(Deny)
	if out := call(); strings.Contains(out, `"ok":true`) || restored != 1 {
		t.Fatalf("an AI tool must not restore without a yes: %s", out)
	}
	r.ans.d.Store(AllowAlways)
	if out := call(); !strings.Contains(out, `"ok":true`) || restored != 2 {
		t.Fatalf("after a yes: %s", out)
	}
	n := r.ans.calls.Load()
	_ = call()
	if r.ans.calls.Load() != n+1 {
		t.Fatal("a restore is asked every time: no standing grant for it")
	}
}

func TestACallerThatAlreadyExitedIsTreatedAsAnAITool(t *testing.T) {
	SetAIChain(func(int) (int, bool) { return 0, false })
	defer SetAIChain(nil)
	if _, ai := classify(1 << 22); !ai { // no such process
		t.Fatal("an unclassifiable caller must not pass as the person")
	}
	if _, ai := classify(os.Getpid()); ai {
		t.Fatal("a live human caller is the person")
	}
}

func TestVaultedKeyIsNeverHandedToAnotherAgent(t *testing.T) {
	r := newRig(t)
	r.move()
	if !r.v.Keys.HasBlob(r.pub.Marshal()) || r.v.Keys.HasBlob([]byte("other")) {
		t.Fatal("HasBlob")
	}
}
