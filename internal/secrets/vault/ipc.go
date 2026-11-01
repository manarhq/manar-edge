package vault

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync/atomic"
	"time"
)

// AIChain tells whether the process pid is a blockable AI tool's chain (or descends from one), and
// which process of the chain is the tool. The watcher package sets it (it owns the tool catalogue).
// nil, or "not an AI tool", means the person's own program.
//
// This is how the person's own shell maps to requests: a sign request or a restore from a program
// with no blockable AI tool above it is answered at once. From an AI tool's chain it is a question
// to the person (WARDEN): once, 8 hours or always for that exact binary (sign), once only (restore);
// no answer in 2 minutes is a denial.
var aiChain atomic.Pointer[func(pid int) (int, bool)]

// SetAIChain installs the classifier (nil removes it).
func SetAIChain(f func(pid int) (toolPID int, ok bool)) {
	if f == nil {
		aiChain.Store(nil)
		return
	}
	aiChain.Store(&f)
}

// AIChain asks the installed classifier; without one nothing is an AI tool.
func AIChain(pid int) (int, bool) {
	if f := aiChain.Load(); f != nil {
		return (*f)(pid)
	}
	return 0, false
}

// HashExe returns the path and SHA-256 of a running process's executable (empty when it cannot be
// read). Set on Linux.
var HashExe func(pid int) (path, sha string)

type ipcRequest struct {
	Op   string `json:"op,omitempty"` // "" (credential) | "restore-all"
	Kind string `json:"kind,omitempty"`
	Ref  string `json:"ref,omitempty"`
}

type ipcReply struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data,omitempty"`
	Error string          `json:"error,omitempty"`
}

// Peer is who is on the other end, as the operating system reports it (not as it says).
type Peer struct {
	PID   int
	Owner string // Who.Key() of the calling user
	Admin bool   // root / elevated administrator
}

// Program is the binary that asked the helper, pinned and hashed.
type Program struct{ Path, SHA string }

// Env is what a connection handler needs from the platform.
type Env struct {
	// Identify pins the helper's parent process and hashes its binary; it also checks that the
	// peer is the manar-edge helper binary. An error means "unidentified", never "allow".
	Identify func(helperPID int) (Program, error)
	// RestoreAll quiesces the module and puts every secret back (admin only).
	RestoreAll func() error
	// AddSSH moves one of the caller's own ssh keys into the vault; RestoreSSH puts the caller's own
	// key (or, with an empty name, all of them) back. owner comes from the operating system.
	AddSSH     func(owner, name string) error
	RestoreSSH func(owner, name string) error
}

func handleConn(ctx context.Context, rw io.ReadWriter, peer Peer, b *Broker, env Env) {
	defer func() { _ = recover() }()
	var req ipcRequest
	line, err := bufio.NewReaderSize(io.LimitReader(rw, 4096), 4096).ReadBytes('\n')
	reply := func(r ipcReply) { out, _ := json.Marshal(r); _, _ = rw.Write(append(out, '\n')) }
	if err != nil || json.Unmarshal(line, &req) != nil {
		reply(ipcReply{Error: "bad request"})
		return
	}
	if (req.Op == "ssh-restore" || req.Op == "restore-all") && aiChain.Load() != nil && peer.PID > 0 {
		// An AI tool running `manar-edge vault restore` is a request to take keys out of the vault:
		// a question to the person, never an answer by itself. Sudo (a person at the terminal) is
		// not in an AI tool's chain.
		if toolPID, ai := AIChain(peer.PID); ai {
			if err := b.AuthorizeRestore(ctx, toolPID, peer.Owner, req.Ref); err != nil {
				reply(ipcReply{Error: err.Error()})
				return
			}
		}
	}
	if req.Op == "restore-all" {
		if !peer.Admin || env.RestoreAll == nil {
			reply(ipcReply{Error: "only an administrator can ask for this"})
			return
		}
		if err := env.RestoreAll(); err != nil {
			reply(ipcReply{Error: err.Error()})
			return
		}
		reply(ipcReply{OK: true, Data: json.RawMessage(`{}`)})
		return
	}
	if req.Op == "ssh-add" || req.Op == "ssh-restore" {
		fn := env.AddSSH
		if req.Op == "ssh-restore" {
			fn = env.RestoreSSH
		}
		if fn == nil || peer.Owner == "" || !(keyNameRe.MatchString(req.Ref) || (req.Op == "ssh-restore" && req.Ref == "")) {
			reply(ipcReply{Error: "bad request"})
			return
		}
		if err := fn(peer.Owner, req.Ref); err != nil {
			reply(ipcReply{Error: err.Error()})
			return
		}
		reply(ipcReply{OK: true, Data: json.RawMessage(`{}`)})
		return
	}
	if req.Op != "" || !profileRe.MatchString(req.Ref) || peer.Owner == "" {
		reply(ipcReply{Error: "bad request"})
		return
	}
	r := Request{Kind: req.Kind, Ref: req.Ref, Owner: peer.Owner}
	if env.Identify != nil {
		if p, err := env.Identify(peer.PID); err == nil {
			r.Program, r.SHA = p.Path, p.SHA
		}
	}
	data, err := b.Credential(ctx, r)
	if err != nil {
		reply(ipcReply{Error: err.Error()})
		return
	}
	reply(ipcReply{OK: true, Data: data})
}

func ask(rw io.ReadWriter, req ipcRequest) ([]byte, error) {
	out, _ := json.Marshal(req)
	if _, err := rw.Write(append(out, '\n')); err != nil {
		return nil, err
	}
	line, err := bufio.NewReader(io.LimitReader(rw, 1<<16)).ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var r ipcReply
	if err := json.Unmarshal(line, &r); err != nil {
		return nil, err
	}
	if !r.OK {
		return nil, errors.New(r.Error)
	}
	return r.Data, nil
}

// RunHelper is `manar-edge secret aws <profile>`: it prints the credential_process JSON.
func RunHelper(kind, ref string, w io.Writer) error {
	c, err := dialDaemon(5 * time.Second)
	if err != nil {
		return errors.New("Manar's service is not running; run `manar-edge secret restore --all` as an administrator to put the keys back")
	}
	defer c.Close()
	data, err := ask(c, ipcRequest{Kind: kind, Ref: ref})
	if err != nil {
		return err
	}
	_, err = w.Write(append(data, '\n'))
	return err
}

// RestoreAllViaService asks the running service to restore every secret (it must be an
// administrator). On Windows the service is the only process that can decrypt the vault. It
// reports whether a service answered; when none did, the caller restores locally.
func RestoreAllViaService() (answered bool, err error) {
	c, derr := dialDaemon(3 * time.Second)
	if derr != nil {
		return false, nil
	}
	defer c.Close()
	_, err = ask(c, ipcRequest{Op: "restore-all"})
	return true, err
}

// SSHViaService asks the running service to move (op "ssh-add") or put back (op "ssh-restore") the
// caller's own ssh key. It reports whether a service answered; none answering is not an error here.
func SSHViaService(op, name string) (answered bool, err error) {
	c, derr := dialDaemon(3 * time.Second)
	if derr != nil {
		return false, nil
	}
	defer c.Close()
	_, err = ask(c, ipcRequest{Op: op, Ref: name})
	return true, err
}
