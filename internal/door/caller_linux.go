package door

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
)

// callerOf names the local user whose socket sent r, from the kernel's TCP table: the row whose
// local address is the request's peer address carries that socket's uid. The peer is on loopback
// (DOOR listens there only), so a process cannot choose its uid, and one that closes its socket
// before the lookup is simply unknown and refused.
func callerOf(r *http.Request) (string, bool) {
	uid, ok := tcpOwnerUID("/proc/net/tcp", r.RemoteAddr)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("uid:%d", uid), true
}

func tcpOwnerUID(table, remote string) (int, bool) {
	host, port, err := net.SplitHostPort(remote)
	if err != nil {
		return 0, false
	}
	ip := net.ParseIP(host).To4()
	var p int
	if ip == nil || func() bool { _, e := fmt.Sscanf(port, "%d", &p); return e != nil }() {
		return 0, false
	}
	want := fmt.Sprintf("%02X%02X%02X%02X:%04X", ip[3], ip[2], ip[1], ip[0], p)
	f, err := os.Open(table)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) > 7 && fs[1] == want && fs[3] == "01" { // established
			var uid int
			if _, err := fmt.Sscanf(fs[7], "%d", &uid); err == nil {
				return uid, true
			}
		}
	}
	return 0, false
}
