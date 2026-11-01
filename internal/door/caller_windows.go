//go:build windows

package door

import (
	"encoding/binary"
	"net"
	"net/http"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procGetExtendedTcpTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

const (
	afInet                = 2
	tcpTableOwnerPidAll   = 5
	errInsufficientBuffer = 122
)

// callerOf names the local user behind r: the TCP table row whose local endpoint is the request's
// peer gives the owning process, and the SID of that process's token is the user.
// MIB_TCPROW_OWNER_PID is six uint32: state, local addr, local port, remote addr, remote port, pid.
func callerOf(r *http.Request) (string, bool) {
	host, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", false
	}
	ip := net.ParseIP(host).To4()
	p, perr := strconv.Atoi(port)
	if ip == nil || perr != nil {
		return "", false
	}
	var size uint32
	_, _, _ = procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, afInet, tcpTableOwnerPidAll, 0)
	if size == 0 {
		return "", false
	}
	buf := make([]byte, size)
	if rc, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, afInet, tcpTableOwnerPidAll, 0); rc != 0 {
		return "", false
	}
	n := int(binary.LittleEndian.Uint32(buf[:4]))
	for i := 0; i < n && 4+(i+1)*24 <= len(buf); i++ {
		row := buf[4+i*24 : 4+(i+1)*24]
		if string(row[4:8]) == string(ip) && int(row[8])<<8|int(row[9]) == p {
			return sidOfPid(binary.LittleEndian.Uint32(row[20:24]))
		}
	}
	return "", false
}

func sidOfPid(pid uint32) (string, bool) {
	if pid == 0 {
		return "", false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", false
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return "", false
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", false
	}
	return "sid:" + u.User.Sid.String(), true
}
