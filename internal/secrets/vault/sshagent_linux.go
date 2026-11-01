//go:build linux

package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/unix"
)

// AgentServer runs Manar's ssh agent: one socket per user who has vaulted keys.
type AgentServer struct {
	V *Vault
	B *Broker
	// Ctx bounds the server; sign requests that wait for a person stop with it.
	Ctx context.Context

	mu sync.Mutex
	ls map[int]*agentListener
}

type agentListener struct {
	l    net.Listener
	path string
	done chan struct{} // closed when the accept loop ends
}

// Ensure makes sure every user with a vaulted key has a working socket, and closes sockets of users
// without one. The module calls it every few seconds, so an agent that died is back within one
// interval. It also reloads the keyring from the vault (keys restored on the command line drop out).
func (s *AgentServer) Ensure() {
	if s.V.Keys == nil {
		return
	}
	_ = s.V.Keys.Sync(s.V)
	want := map[int]bool{}
	for _, o := range s.V.Keys.Owners() {
		if uid, ok := ownerUID(o); ok {
			want[uid] = true
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ls == nil {
		s.ls = map[int]*agentListener{}
	}
	for uid, al := range s.ls {
		select {
		case <-al.done:
			delete(s.ls, uid) // the accept loop died
		default:
			if _, err := os.Lstat(al.path); err != nil { // the socket file was removed
				al.l.Close()
				delete(s.ls, uid)
			}
		}
		if !want[uid] {
			if al2, ok := s.ls[uid]; ok {
				al2.l.Close()
				_ = os.Remove(al2.path)
				delete(s.ls, uid)
			}
		}
	}
	for uid := range want {
		if _, ok := s.ls[uid]; ok {
			continue
		}
		al, err := s.listen(uid)
		if err != nil {
			log.Printf("manar-edge: ssh agent for uid %d: %v", uid, err)
			continue
		}
		s.ls[uid] = al
	}
}

// Close stops every socket (the keys stay in the vault).
func (s *AgentServer) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for uid, al := range s.ls {
		al.l.Close()
		_ = os.Remove(al.path)
		delete(s.ls, uid)
	}
}

func (s *AgentServer) listen(uid int) (*agentListener, error) {
	path := AgentSocket(uid)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	gid := 0
	if w, err := WhoOfHome(homeOfUID(s.V, uid)); err == nil {
		gid = w.GID
	}
	if err := os.Chown(path, uid, gid); err != nil && os.Geteuid() == 0 {
		l.Close()
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	al := &agentListener{l: l, path: path, done: make(chan struct{})}
	go func() {
		defer close(al.done)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go s.serve(c, uid)
		}
	}()
	return al, nil
}

func homeOfUID(v *Vault, uid int) string {
	for _, h := range v.Homes() {
		if w, err := WhoOfHome(h); err == nil && w.UID == uid {
			return h
		}
	}
	return ""
}

func init() { HashExe = hashExe }

// classify decides, once, at accept time and while the caller is certainly the process that
// connected (a pidfd is opened first and checked again after), whether the caller is an AI tool's
// chain. A caller that has already exited cannot be classified and is treated as one: a program
// that connects and exits (setsid, a background job) must not pass as the person.
func classify(pid int) (toolPID int, ai bool) {
	pfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return 0, true
	}
	defer unix.Close(pfd)
	toolPID, ai = AIChain(pid)
	if unix.PidfdSendSignal(pfd, 0, nil, 0) != nil { // gone while we looked
		return 0, true
	}
	return toolPID, ai
}

func (s *AgentServer) serve(c net.Conn, uid int) {
	defer c.Close()
	defer func() { _ = recover() }()
	pid, puid := peerCred(c)
	if pid <= 0 || puid != uid { // only the owner of the socket
		return
	}
	toolPID, ai := classify(pid)
	_ = c.SetDeadline(time.Now().Add(10 * time.Minute))
	ag := &connAgent{s: s, uid: uid, pid: pid, owner: "u" + strconv.Itoa(uid), toolPID: toolPID, ai: ai}
	defer func() {
		if ag.upConn != nil {
			ag.upConn.Close()
		}
	}()
	if err := agent.ServeAgent(ag, c); err != nil && !errors.Is(err, io.EOF) {
		_ = err
	}
}

// connAgent answers one connection.
type connAgent struct {
	s     *AgentServer
	uid   int
	pid   int
	owner string
	// toolPID and ai are the classification made at accept.
	toolPID int
	ai      bool

	upTried bool
	up      agent.ExtendedAgent
	upConn  net.Conn
}

var errNoSupport = errors.New("not supported by Manar's agent")

func (a *connAgent) List() ([]*agent.Key, error) {
	var out []*agent.Key
	for _, h := range a.s.V.Keys.For(a.owner) {
		out = append(out, &agent.Key{Format: h.Signer.PublicKey().Type(), Blob: h.Signer.PublicKey().Marshal(), Comment: "manar:" + h.Name})
	}
	if up := a.upstream(); up != nil {
		if ks, err := up.List(); err == nil {
			for _, k := range ks {
				if !a.s.V.Keys.HasBlob(k.Blob) { // the old agent may still hold a moved key
					out = append(out, k)
				}
			}
		}
	}
	return out, nil
}

func (a *connAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *connAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	blob := key.Marshal()
	for _, h := range a.s.V.Keys.For(a.owner) {
		if !bytes.Equal(h.Signer.PublicKey().Marshal(), blob) {
			continue
		}
		if err := a.authorize(h.Name); err != nil {
			return nil, err
		}
		if as, ok := h.Signer.(ssh.AlgorithmSigner); ok && flags != 0 {
			alg := h.Signer.PublicKey().Type()
			switch {
			case flags&agent.SignatureFlagRsaSha512 != 0:
				alg = ssh.KeyAlgoRSASHA512
			case flags&agent.SignatureFlagRsaSha256 != 0:
				alg = ssh.KeyAlgoRSASHA256
			}
			return as.SignWithAlgorithm(rand0(), data, alg)
		}
		return h.Signer.Sign(rand0(), data)
	}
	if a.s.V.Keys.HasBlob(blob) { // never hand a vaulted key's request to another agent
		return nil, errors.New("no such key")
	}
	if up := a.upstream(); up != nil { // the user's other keys keep working
		if ea, ok := up.(agent.ExtendedAgent); ok {
			return ea.SignWithFlags(key, data, flags)
		}
		return up.Sign(key, data)
	}
	return nil, errors.New("no such key")
}

// authorize is the sign decision (see AIChain).
func (a *connAgent) authorize(keyName string) error {
	if !a.ai {
		return nil
	}
	path, sha := "", ""
	if a.toolPID > 0 {
		path, sha = hashExe(a.toolPID)
	}
	ctx := a.s.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute+10*time.Second)
	defer cancel()
	return a.s.B.Authorize(ctx, Request{Kind: "ssh", Ref: keyName, Owner: a.owner, Program: path, SHA: sha})
}

// hashExe hashes the executable of a running process through its /proc link (the file itself, not
// a path). Failure gives empty values: the question is still asked, but no standing grant is kept.
func hashExe(pid int) (path, sha string) {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return "", ""
	}
	defer f.Close()
	path, _ = os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", ""
	}
	return strings.TrimSuffix(path, " (deleted)"), hex.EncodeToString(h.Sum(nil))
}

func (a *connAgent) Add(k agent.AddedKey) error {
	if up := a.upstream(); up != nil {
		return up.Add(k)
	}
	return errNoSupport
}
func (a *connAgent) Remove(key ssh.PublicKey) error {
	if up := a.upstream(); up != nil {
		return up.Remove(key)
	}
	return errNoSupport
}
func (a *connAgent) RemoveAll() error {
	if up := a.upstream(); up != nil {
		return up.RemoveAll()
	}
	return errNoSupport
}
func (a *connAgent) Lock([]byte) error              { return errNoSupport }
func (a *connAgent) Unlock([]byte) error            { return errNoSupport }
func (a *connAgent) Signers() ([]ssh.Signer, error) { return nil, errNoSupport }
func (a *connAgent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

// upstream is the agent the user had before Manar's snippet replaced SSH_AUTH_SOCK, named by the
// caller's environment (MANAR_UPSTREAM_SSH_AUTH_SOCK). It must be a socket owned by the caller and
// not one of Manar's. We only ever connect to it.
//
// ponytail: a client can name any socket it owns; the worst result is a failed or bogus list from
// its own socket. Pin the path from the vault entry if that is ever not enough.
func (a *connAgent) upstream() agent.ExtendedAgent {
	if !a.upTried {
		a.upTried = true
		a.up, a.upConn = a.dialUpstream()
	}
	return a.up
}

func (a *connAgent) dialUpstream() (agent.ExtendedAgent, net.Conn) {
	env, err := os.ReadFile("/proc/" + strconv.Itoa(a.pid) + "/environ")
	if err != nil {
		return nil, nil
	}
	const k = "MANAR_UPSTREAM_SSH_AUTH_SOCK="
	var sock string
	for _, kv := range bytes.Split(env, []byte{0}) {
		if bytes.HasPrefix(kv, []byte(k)) {
			sock = string(kv[len(k):])
		}
	}
	if sock == "" || !filepath.IsAbs(sock) || strings.HasPrefix(sock, "/run/manar-edge/") {
		return nil, nil
	}
	if uid, ok := fileOwner(sock); !ok || uid != a.uid {
		return nil, nil
	}
	c, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		return nil, nil
	}
	cl := agent.NewClient(c).(agent.ExtendedAgent)
	for _, h := range a.s.V.Keys.For(a.owner) { // the old agent must not keep serving a key that moved
		_ = cl.Remove(h.Signer.PublicKey())
	}
	return cl, c
}
