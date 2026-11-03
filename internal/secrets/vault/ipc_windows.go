//go:build windows

package vault

import (
	"context"
	"errors"
	"io"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const pipeName = `\\.\pipe\manar-edge-vault`

// pipeSDDL: protected DACL, SYSTEM full control, authenticated users FILE_GENERIC_READ |
// FILE_WRITE_DATA (0x12008b) and nothing else. Not FILE_APPEND_DATA: on a pipe that is the right to
// create an instance, which would let any user serve this name next to the service.
const pipeSDDL = "D:P(A;;GA;;;SY)(A;;0x12008b;;;AU)"

// dialDaemon connects to the service's pipe and checks that the process serving it runs as
// SYSTEM, so a user who created the name first (or while the service was stopped) is not trusted
// with a credential request or a restore.
func dialDaemon(timeout time.Duration) (io.ReadWriteCloser, error) {
	n, err := windows.UTF16PtrFromString(pipeName)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for {
		h, err := windows.CreateFile(n, windows.FILE_GENERIC_READ|windows.FILE_WRITE_DATA, 0, nil, windows.OPEN_EXISTING,
			windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == nil {
			var pid uint32
			if windows.GetNamedPipeServerProcessId(h, &pid) != nil || !isSystem(pid) {
				windows.CloseHandle(h)
				return nil, errors.New("the vault pipe is not served by the Manar service")
			}
			return os.NewFile(uintptr(h), pipeName), nil
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// Serve answers helper calls over the named pipe until ctx ends.
func Serve(ctx context.Context, b *Broker, env Env) error {
	sd, err := windows.SecurityDescriptorFromString(pipeSDDL)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	n, _ := windows.UTF16PtrFromString(pipeName)
	create := func(first bool) (windows.Handle, error) {
		flags := uint32(windows.PIPE_ACCESS_DUPLEX)
		if first {
			flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
		}
		return windows.CreateNamedPipe(n, flags,
			windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
			windows.PIPE_UNLIMITED_INSTANCES, 64<<10, 64<<10, 0, sa)
	}
	next, err := create(true)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		if c, err := dialDaemon(time.Second); err == nil { // wake the pending Connect
			c.Close()
		}
	}()
	for {
		cur := next
		if err := windows.ConnectNamedPipe(cur, nil); err != nil && err != windows.ERROR_PIPE_CONNECTED {
			windows.CloseHandle(cur)
			return err
		}
		if ctx.Err() != nil {
			windows.CloseHandle(cur)
			return nil
		}
		if next, err = create(false); err != nil {
			windows.CloseHandle(cur)
			return err
		}
		go func() {
			// One owner for the handle, closed once here: no os.File wraps it.
			defer func() {
				_ = windows.FlushFileBuffers(cur)
				_ = windows.DisconnectNamedPipe(cur)
				_ = windows.CloseHandle(cur)
			}()
			var pid uint32
			if windows.GetNamedPipeClientProcessId(cur, &pid) != nil || pid == 0 {
				return
			}
			owner, admin, err := peerOf(pid)
			if err != nil {
				return
			}
			handleConn(ctx, pipeRW{cur}, Peer{PID: int(pid), Owner: owner, Admin: admin}, b, env)
		}()
	}
}

// pipeRW reads and writes a pipe handle directly.
type pipeRW struct{ h windows.Handle }

func (p pipeRW) Read(b []byte) (int, error) {
	var n uint32
	err := windows.ReadFile(p.h, b, &n, nil)
	if n > 0 {
		return int(n), nil
	}
	if err != nil {
		return 0, io.EOF
	}
	return 0, nil
}

func (p pipeRW) Write(b []byte) (int, error) {
	var n uint32
	err := windows.WriteFile(p.h, b, &n, nil)
	return int(n), err
}

// isSystem reports whether the process runs as LocalSystem.
func isSystem(pid uint32) bool {
	owner, _, err := peerOf(pid)
	return err == nil && owner == "S-1-5-18"
}
