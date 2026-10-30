//go:build windows

package vault

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// parentExe returns the image path of pid's parent ("" when unknown).
func parentExe(pid int) string {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if int(e.ProcessID) != pid {
			continue
		}
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, e.ParentProcessID)
		if err != nil {
			return ""
		}
		defer windows.CloseHandle(h)
		buf := make([]uint16, 1024)
		n := uint32(len(buf))
		if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) != nil {
			return ""
		}
		return windows.UTF16ToString(buf[:n])
	}
	return ""
}
