//go:build windows

package warden

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// PipeName is the named pipe the service creates in session 0 and the helper opens.
const PipeName = `\\.\pipe\manar-warden`

func userSIDFile(base string) string { return filepath.Join(Dir(base), "user-sid") }

func listen(base string) (net.Listener, PeerCheck, error) {
	b, err := os.ReadFile(userSIDFile(base))
	if err != nil {
		return nil, nil, errors.New("warden: no user is set up for the Windows prompt (reinstall from the user's session)")
	}
	sddl, err := PipeSDDL(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, nil, err
	}
	l, err := winio.ListenPipe(PipeName, &winio.PipeConfig{SecurityDescriptor: sddl, InputBufferSize: 65536, OutputBufferSize: 65536})
	if err != nil {
		return nil, nil, err
	}
	want, err := ownImage()
	if err == nil && !InProtectedDir(want, os.Getenv("ProgramFiles")) {
		// A copy anyone can overwrite (a user's Downloads, a temp folder) must not be the helper.
		err = errors.New("warden: manar-edge is not running from Program Files; use the installed copy")
	}
	if err != nil {
		l.Close()
		return nil, nil, err
	}
	// The pipe's DACL lets only SYSTEM and that one SID open it (and not create instances). On top
	// of that, the client must be a running manar-edge from the installed path, so another
	// program of the same user cannot act as the helper.
	return l, func(c net.Conn) (string, error) {
		pid, err := pipePID(c, windows.GetNamedPipeClientProcessId)
		if err != nil {
			return "", err
		}
		img, err := imageOf(pid)
		if err != nil {
			return "", err
		}
		if !strings.EqualFold(img, want) {
			return "", errors.New("the peer is not the installed manar-edge")
		}
		return "pipe-user", nil
	}, nil
}

// Dial connects the helper. It then checks that the server is the service, a manar-edge from the
// same installed path, not a fake server another program of the user started.
func Dial(ctx context.Context) (net.Conn, error) {
	c, err := winio.DialPipeContext(ctx, PipeName)
	if err != nil {
		return nil, err
	}
	want, err := ownImage()
	if err == nil {
		var pid uint32
		if pid, err = pipePID(c, windows.GetNamedPipeServerProcessId); err == nil {
			var img string
			if img, err = imageOf(pid); err == nil && !strings.EqualFold(img, want) {
				err = errors.New("the pipe server is not the installed manar-edge")
			}
		}
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func pipePID(c net.Conn, get func(windows.Handle, *uint32) error) (uint32, error) {
	f, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return 0, errors.New("warden: not a pipe connection")
	}
	var pid uint32
	if err := get(windows.Handle(f.Fd()), &pid); err != nil {
		return 0, err
	}
	return pid, nil
}

func ownImage() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// imageOf is the full path of a process's executable.
func imageOf(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 1024)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(windows.UTF16ToString(buf[:n]))
}
