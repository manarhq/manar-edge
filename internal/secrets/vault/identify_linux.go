//go:build linux

package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func ppidOf(pid int) (int, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, err
	}
	s := string(b)
	f := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
	if len(f) < 2 {
		return 0, errors.New("short stat")
	}
	return strconv.Atoi(f[1])
}

// Identify pins the parent of the helper with a pidfd, hashes the binary it runs, and checks the
// pidfd is still alive and the parent unchanged afterwards, so a parent that exited and was
// replaced between the steps is refused. The peer itself must be this very manar-edge binary.
func Identify(helperPID int) (Program, error) {
	self, err := os.Executable()
	if err != nil {
		return Program{}, err
	}
	self, _ = filepath.EvalSymlinks(self)
	peerExe, err := os.Readlink("/proc/" + strconv.Itoa(helperPID) + "/exe")
	if err != nil || strings.TrimSuffix(peerExe, " (deleted)") != self {
		return Program{}, errors.New("the caller is not the manar-edge helper")
	}
	ppid, err := ppidOf(helperPID)
	if err != nil || ppid <= 1 {
		return Program{}, errors.New("no parent process")
	}
	pfd, err := unix.PidfdOpen(ppid, 0)
	if err != nil {
		return Program{}, err
	}
	defer unix.Close(pfd)
	exe, err := os.Open("/proc/" + strconv.Itoa(ppid) + "/exe") // the binary itself, not a path
	if err != nil {
		return Program{}, err
	}
	defer exe.Close()
	path, err := os.Readlink("/proc/" + strconv.Itoa(ppid) + "/exe")
	if err != nil {
		return Program{}, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, exe); err != nil {
		return Program{}, err
	}
	again, err := ppidOf(helperPID)
	if err != nil || again != ppid || unix.PidfdSendSignal(pfd, 0, nil, 0) != nil {
		return Program{}, errors.New("the parent process changed while it was being identified")
	}
	return Program{Path: strings.TrimSuffix(path, " (deleted)"), SHA: hex.EncodeToString(h.Sum(nil))}, nil
}
