package jail

import (
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
