//go:build !windows

package undo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"time"
)

// ErrNoUser: the account no longer exists, so there is nothing to act for.
var ErrNoUser = errors.New("unknown user")

// RunAs runs `exe args...` as the user with uid and no other groups (the service is root; it never
// touches a user's files itself). When the service is not root it can only act for its own user.
func RunAs(uid int, exe string, args ...string) ([]byte, error) {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoUser, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return nil, errors.New("bad group id")
	}
	if os.Geteuid() != 0 && os.Geteuid() != uid {
		return nil, errors.New("the service cannot act for this user")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + u.HomeDir}
	if os.Geteuid() == 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}}}
	}
	var out bytes.Buffer
	cmd.Stdout = &limited{w: &out, n: 1 << 16}
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("helper failed: %w", err)
	}
	return out.Bytes(), nil
}

type limited struct {
	w interface{ Write([]byte) (int, error) }
	n int
}

func (l *limited) Write(p []byte) (int, error) {
	if len(p) > l.n {
		return 0, errors.New("output too large")
	}
	l.n -= len(p)
	return l.w.Write(p)
}
