package jail

import (
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

// runningClaudeExes lists the image paths of running claude.exe processes (any account).
func runningClaudeExes() []string {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var out []string
	for err := windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if windows.UTF16ToString(e.ExeFile[:]) != "claude.exe" {
			continue
		}
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, e.ProcessID)
		if err != nil {
			continue
		}
		buf := make([]uint16, 1024)
		n := uint32(len(buf))
		if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil {
			out = append(out, windows.UTF16ToString(buf[:n]))
		}
		windows.CloseHandle(h)
	}
	return out
}

// windowsResolvers lists the DNS servers of the adapters that are up (what a program's own name
// lookups go to). The site-local placeholders Windows lists for IPv6 (fec0:0:0:ffff::) are skipped.
func windowsResolvers() []netip.Addr {
	size := uint32(15000)
	var buf []byte
	for range 3 {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_FRIENDLY_NAME,
			0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return nil
		}
	}
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next {
		if aa.OperStatus != windows.IfOperStatusUp {
			continue
		}
		for d := aa.FirstDnsServerAddress; d != nil; d = d.Next {
			if d.Address.Sockaddr == nil {
				continue
			}
			sa, err := (*windows.RawSockaddrAny)(unsafe.Pointer(d.Address.Sockaddr)).Sockaddr()
			if err != nil {
				continue
			}
			var a netip.Addr
			switch v := sa.(type) {
			case *windows.SockaddrInet4:
				a = netip.AddrFrom4(v.Addr)
			case *windows.SockaddrInet6:
				a = netip.AddrFrom16(v.Addr)
			default:
				continue
			}
			if a.Is6() && a.As16()[0] == 0xfe && a.As16()[1]&0xc0 == 0xc0 { // fec0::/10
				continue
			}
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	return out
}
