package protect

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// On Windows the relay is a named pipe. Its DACL gives SYSTEM and Administrators full control and
// authenticated users FILE_GENERIC_READ | FILE_WRITE_DATA (0x12008b), not FILE_APPEND_DATA, which on
// a pipe is the right to create an instance; the service creates
// the first instance with FILE_FLAG_FIRST_PIPE_INSTANCE, so a squatter makes the service fail
// instead of being trusted, and the client checks the pipe's server runs as SYSTEM. The calling
// user's SID goes into the audit record.
var errEOF = io.EOF

const (
	relayPipe = `\\.\pipe\manar-edge-relay`
	relaySDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12008b;;;AU)"
)

type pipeConn struct {
	h      windows.Handle
	server bool
}

func (p *pipeConn) Read(b []byte) (int, error) {
	var n uint32
	if err := windows.ReadFile(p.h, b, &n, nil); err != nil {
		if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED) {
			return int(n), errEOF
		}
		return int(n), err
	}
	return int(n), nil
}

func (p *pipeConn) Write(b []byte) (int, error) {
	var n uint32
	err := windows.WriteFile(p.h, b, &n, nil)
	return int(n), err
}

func (p *pipeConn) Close() error {
	if p.server {
		windows.FlushFileBuffers(p.h)
		windows.DisconnectNamedPipe(p.h)
	}
	return windows.CloseHandle(p.h)
}

type pipeAddr struct{}

func (pipeAddr) Network() string                     { return "pipe" }
func (pipeAddr) String() string                      { return relayPipe }
func (p *pipeConn) LocalAddr() net.Addr              { return pipeAddr{} }
func (p *pipeConn) RemoteAddr() net.Addr             { return pipeAddr{} }
func (p *pipeConn) SetDeadline(time.Time) error      { return nil }
func (p *pipeConn) SetReadDeadline(time.Time) error  { return nil }
func (p *pipeConn) SetWriteDeadline(time.Time) error { return nil }

type pipeListener struct {
	sa    *windows.SecurityAttributes
	next  windows.Handle
	done  chan struct{}
	first bool
}

func newInstance(sa *windows.SecurityAttributes, first bool) (windows.Handle, error) {
	n, err := windows.UTF16PtrFromString(relayPipe)
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.PIPE_ACCESS_DUPLEX)
	if first {
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	return windows.CreateNamedPipe(n, flags,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		windows.PIPE_UNLIMITED_INSTANCES, 64<<10, 64<<10, 0, sa)
}

func listenRelay() (net.Listener, error) {
	sd, err := windows.SecurityDescriptorFromString(relaySDDL)
	if err != nil {
		return nil, err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := newInstance(sa, true)
	if err != nil {
		return nil, err
	}
	return &pipeListener{sa: sa, next: h, done: make(chan struct{})}, nil
}

func (l *pipeListener) Accept() (net.Conn, error) {
	h := l.next
	if err := windows.ConnectNamedPipe(h, nil); err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		windows.CloseHandle(h)
		select {
		case <-l.done:
			return nil, net.ErrClosed
		default:
		}
		return nil, err
	}
	next, err := newInstance(l.sa, false)
	if err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	l.next = next
	return &pipeConn{h: h, server: true}, nil
}

func (l *pipeListener) Close() error {
	close(l.done)
	// Wake the pending ConnectNamedPipe by connecting to it once.
	if c, err := openPipe(); err == nil {
		windows.CloseHandle(c)
	}
	return nil
}
func (l *pipeListener) Addr() net.Addr { return pipeAddr{} }

func openPipe() (windows.Handle, error) {
	n, err := windows.UTF16PtrFromString(relayPipe)
	if err != nil {
		return 0, err
	}
	for i := 0; i < 20; i++ {
		// Only the rights the DACL grants, and identification-level impersonation: whoever serves
		// the pipe cannot act as the caller (Close connects as SYSTEM to wake the listener).
		h, err := windows.CreateFile(n, windows.FILE_GENERIC_READ|windows.FILE_WRITE_DATA, 0, nil, windows.OPEN_EXISTING,
			windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == nil {
			return h, nil
		}
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) {
			return 0, err
		}
		time.Sleep(50 * time.Millisecond)
	}
	return 0, windows.ERROR_PIPE_BUSY
}

func dialRelay(context.Context) (net.Conn, error) {
	h, err := openPipe()
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return nil, &downError{err}
		}
		return nil, err
	}
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(h, &pid); err != nil || userSID(pid) != "S-1-5-18" {
		windows.CloseHandle(h)
		return nil, errors.New("the relay pipe is not served by the service")
	}
	return &pipeConn{h: h}, nil
}

func userSID(pid uint32) string {
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(p)
	var tok windows.Token
	if err := windows.OpenProcessToken(p, windows.TOKEN_QUERY, &tok); err != nil {
		return ""
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return ""
	}
	return u.User.Sid.String()
}

func callerOf(c net.Conn) string {
	pc, ok := c.(*pipeConn)
	if !ok {
		return "unknown"
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(pc.h, &pid); err != nil {
		return "unknown"
	}
	if sid := userSID(pid); sid != "" {
		return "sid:" + sid
	}
	return "unknown"
}
