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
	// The pipe's DACL is the check: only SYSTEM and that one SID can open it at all.
	return l, func(net.Conn) error { return nil }, nil
}

func Dial(ctx context.Context) (net.Conn, error) { return winio.DialPipeContext(ctx, PipeName) }
