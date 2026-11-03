//go:build windows

package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func openQuery(pid uint32) (windows.Handle, error) {
	return windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
}

func imagePath(h windows.Handle) (string, error) {
	buf := make([]uint16, 1024)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:n]), nil
}

func started(h windows.Handle) (int64, error) {
	var c, e, k, u windows.Filetime
	if err := windows.GetProcessTimes(h, &c, &e, &k, &u); err != nil {
		return 0, err
	}
	return c.Nanoseconds(), nil
}

// Identify holds handles to the helper and its parent (a handle cannot be recycled to another
// process), requires the parent to have started before the helper and to still be running, and
// hashes the parent's image. The peer must be this manar-edge binary. A recorded parent cannot be
// verified on Windows (any program of the same user can name another parent when it starts a
// process), so the path and hash only inform the person: no standing grant is kept or used on
// Windows (standingGrants in broker.go), and every release asks.
func Identify(helperPID int) (Program, error) {
	self, err := os.Executable()
	if err != nil {
		return Program{}, err
	}
	hp, err := openQuery(uint32(helperPID))
	if err != nil {
		return Program{}, err
	}
	defer windows.CloseHandle(hp)
	if p, err := imagePath(hp); err != nil || !samePath(p, self) {
		return Program{}, errors.New("the caller is not the manar-edge helper")
	}
	ppid, err := parentPID(uint32(helperPID))
	if err != nil {
		return Program{}, err
	}
	pp, err := openQuery(ppid)
	if err != nil {
		return Program{}, err
	}
	defer windows.CloseHandle(pp)
	pt, err1 := started(pp)
	ht, err2 := started(hp)
	if err1 != nil || err2 != nil || pt > ht {
		return Program{}, errors.New("the parent process is not the one that started the helper")
	}
	path, err := imagePath(pp)
	if err != nil {
		return Program{}, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Program{}, err
	}
	sum := sha256.Sum256(b)
	if ev, _ := windows.WaitForSingleObject(pp, 0); ev != uint32(windows.WAIT_TIMEOUT) {
		return Program{}, errors.New("the parent process exited while it was being identified")
	}
	return Program{Path: path, SHA: hex.EncodeToString(sum[:])}, nil
}

func samePath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	return len(a) == len(b) && windows.UTF16ToString(windows.StringToUTF16(a)) == windows.UTF16ToString(windows.StringToUTF16(b)) ||
		equalFold(a, b)
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 32
		}
		if 'A' <= y && y <= 'Z' {
			y += 32
		}
		if x != y {
			return false
		}
	}
	return true
}

func parentPID(pid uint32) (uint32, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if e.ProcessID == pid {
			return e.ParentProcessID, nil
		}
	}
	return 0, errors.New("process not found")
}

// peerOf reads the caller's SID and whether it is an elevated administrator from its token.
func peerOf(pid uint32) (owner string, admin bool, err error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", false, err
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return "", false, err
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", false, err
	}
	return u.User.Sid.String(), tok.IsElevated(), nil
}
