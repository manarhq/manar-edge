package protect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

type fsReq struct {
	Op   string `json:"op"` // read, write, remove
	Home string `json:"home"`
	Path string `json:"path"`
	Data []byte `json:"data,omitempty"`
	Mode uint32 `json:"mode,omitempty"`
}

type fsResp struct {
	Exists bool   `json:"exists"`
	Mode   uint32 `json:"mode"`
	Data   []byte `json:"data,omitempty"`
	Err    string `json:"err,omitempty"`
	Link   bool   `json:"link,omitempty"`
}

// ServeUserFS is `manar-edge __userfs`: it reads one request, runs it as the current (already
// unprivileged) user, and prints the answer. It never runs as root for a user's files.
func ServeUserFS(in io.Reader, out io.Writer) int {
	var req fsReq
	if err := json.NewDecoder(io.LimitReader(in, 64<<20)).Decode(&req); err != nil {
		return 2
	}
	d := directFS{Home: req.Home}
	var resp fsResp
	switch req.Op {
	case "read":
		data, exists, mode, err := d.Read(req.Path)
		resp = fsResp{Exists: exists, Mode: uint32(mode), Data: data}
		setErr(&resp, err)
	case "write":
		setErr(&resp, d.Write(req.Path, req.Data, os.FileMode(req.Mode)))
	case "remove":
		setErr(&resp, d.Remove(req.Path))
	default:
		return 2
	}
	_ = json.NewEncoder(out).Encode(resp)
	return 0
}

func setErr(r *fsResp, err error) {
	if err != nil {
		r.Err, r.Link = err.Error(), errors.Is(err, errLink)
	}
}

// asUserFS runs each call in a child process with the owner's uid and gid and no other groups.
type asUserFS struct {
	UID, GID int
	Home     string
	Exe      string
}

func (a asUserFS) do(req fsReq) (fsResp, error) {
	req.Home = a.Home
	in, _ := json.Marshal(req)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command (re-exec of this binary)
	cmd := exec.CommandContext(ctx, a.Exe, "__userfs")
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(a.UID), Gid: uint32(a.GID), Groups: []uint32{}}}
	cmd.Stdin = bytes.NewReader(in)
	var out bytes.Buffer
	cmd.Stdout = &limitWriter{w: &out, n: 64 << 20}
	if err := cmd.Run(); err != nil {
		return fsResp{}, fmt.Errorf("cannot act as the file's owner: %w", err)
	}
	var resp fsResp
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		return fsResp{}, errors.New("unreadable answer from the user-level helper")
	}
	if resp.Err != "" {
		if resp.Link {
			return resp, fmt.Errorf("%s", resp.Err)
		}
		return resp, errors.New(resp.Err)
	}
	return resp, nil
}

type limitWriter struct {
	w io.Writer
	n int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if len(p) > l.n {
		return 0, errors.New("output too large")
	}
	l.n -= len(p)
	return l.w.Write(p)
}

func (a asUserFS) Read(path string) ([]byte, bool, os.FileMode, error) {
	r, err := a.do(fsReq{Op: "read", Path: path})
	return r.Data, r.Exists, os.FileMode(r.Mode), err
}

func (a asUserFS) Write(path string, data []byte, mode os.FileMode) error {
	_, err := a.do(fsReq{Op: "write", Path: path, Data: data, Mode: uint32(mode)})
	return err
}

func (a asUserFS) Remove(path string) error {
	_, err := a.do(fsReq{Op: "remove", Path: path})
	return err
}

// newUserFS is what Store uses: the owner's own identity when we are root, else this process.
func newUserFS(o Owner) FS {
	if os.Geteuid() == 0 && o.UID > 0 {
		return asUserFS{UID: o.UID, GID: o.GID, Home: o.Home, Exe: exePath()}
	}
	return directFS{Home: o.Home}
}
