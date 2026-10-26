package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Claude Code hook on Windows reaches the gateway over a named pipe, not loopback TCP: any
// process could bind 127.0.0.1:8480 while the gateway service restarts and answer the hook. The
// pipe's DACL (pipeSDDL) lets Users read and write but not create instances, the service creates
// the first instance with FILE_FLAG_FIRST_PIPE_INSTANCE (a squatter makes the service fail
// instead of being trusted), and the hook checks that the pipe's server process is the service.
//
// Each connection carries one HTTP request and one response, read and written in turn, so plain
// synchronous pipe handles are enough.

func pipeName(name string) string { return `\\.\pipe\manar-edge-` + name }

func createPipe(name string, sa *windows.SecurityAttributes, first bool) (windows.Handle, error) {
	n, err := windows.UTF16PtrFromString(name)
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

// serveHook serves h on the agent's pipe until ctx ends.
func serveHook(ctx context.Context, st *State, h http.Handler) error {
	sd, err := windows.SecurityDescriptorFromString(pipeSDDL)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name := pipeName(st.Name)
	next, err := createPipe(name, sa, true)
	if err != nil {
		return fmt.Errorf("hook pipe %s: %w (is another process holding the name?)", name, err)
	}
	var closed atomic.Bool
	go func() {
		<-ctx.Done()
		closed.Store(true)
		if c, err := openPipe(name); err == nil { // wake the pending ConnectNamedPipe
			windows.CloseHandle(c)
		}
	}()
	for {
		cur := next
		if err := windows.ConnectNamedPipe(cur, nil); err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
			windows.CloseHandle(cur)
			return err
		}
		if closed.Load() {
			windows.CloseHandle(cur)
			return nil
		}
		// Keep an instance pending at all times, so the name is never free for someone else.
		if next, err = createPipe(name, sa, false); err != nil {
			windows.CloseHandle(cur)
			return err
		}
		go servePipeConn(cur, h)
	}
}

func servePipeConn(hd windows.Handle, h http.Handler) {
	c := &pipeConn{h: hd}
	defer func() {
		_ = windows.FlushFileBuffers(hd)
		_ = windows.DisconnectNamedPipe(hd)
		_ = windows.CloseHandle(hd)
	}()
	req, err := http.ReadRequest(bufio.NewReader(io.LimitReader(c, 1<<20)))
	if err != nil {
		return
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := rec.Result()
	res.ContentLength = int64(rec.Body.Len())
	res.Close = true
	_ = res.Write(c)
}

func openPipe(name string) (windows.Handle, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	// Read and write data only (no FILE_APPEND_DATA, which the DACL does not grant), and
	// identification-level impersonation so the server cannot act as the caller.
	return windows.CreateFile(n, windows.FILE_GENERIC_READ|windows.FILE_WRITE_DATA, 0, nil, windows.OPEN_EXISTING,
		windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
}

// servicePID returns the process id of a running service, with rights any user has.
func servicePID(service string) (uint32, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(scm)
	n, err := windows.UTF16PtrFromString(service)
	if err != nil {
		return 0, err
	}
	s, err := windows.OpenService(scm, n, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0, err
	}
	defer windows.CloseServiceHandle(s)
	var st windows.SERVICE_STATUS_PROCESS
	var need uint32
	if err := windows.QueryServiceStatusEx(s, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&st)), uint32(unsafe.Sizeof(st)), &need); err != nil {
		return 0, err
	}
	if st.CurrentState != windows.SERVICE_RUNNING || st.ProcessId == 0 {
		return 0, errors.New("service is not running")
	}
	return st.ProcessId, nil
}

// pipeRoundTripper sends one request per pipe connection, after checking the pipe is served by
// the gateway service.
type pipeRoundTripper struct{ pipe, service string }

func (p pipeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	var hd windows.Handle
	for {
		var err error
		if hd, err = openPipe(p.pipe); err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) {
			return nil, err
		}
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	var pid uint32
	want, err := servicePID(p.service)
	if err == nil {
		err = windows.GetNamedPipeServerProcessId(hd, &pid)
	}
	if err != nil || pid != want {
		windows.CloseHandle(hd)
		return nil, errors.New("the hook pipe is not served by the " + p.service + " service")
	}
	c := &pipeConn{h: hd}
	req.Close = true
	if err := req.Write(c); err != nil {
		c.Close()
		return nil, err
	}
	res, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		c.Close()
		return nil, err
	}
	res.Body = &bodyCloser{ReadCloser: res.Body, c: c}
	return res, nil
}

type bodyCloser struct {
	io.ReadCloser
	c io.Closer
}

func (b *bodyCloser) Close() error { b.ReadCloser.Close(); return b.c.Close() }

// pipeConn is a synchronous pipe handle as an io.ReadWriteCloser.
type pipeConn struct{ h windows.Handle }

func (c *pipeConn) Read(b []byte) (int, error) {
	var n uint32
	err := windows.ReadFile(c.h, b, &n, nil)
	if errors.Is(err, windows.ERROR_BROKEN_PIPE) || (err == nil && n == 0 && len(b) > 0) {
		return int(n), io.EOF
	}
	return int(n), err
}

func (c *pipeConn) Write(b []byte) (int, error) {
	var n uint32
	err := windows.WriteFile(c.h, b, &n, nil)
	return int(n), err
}

func (c *pipeConn) Close() error { return windows.CloseHandle(c.h) }
