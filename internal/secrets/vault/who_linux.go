//go:build linux

package vault

import (
	"errors"
	"os"
	"runtime"
	"syscall"
)

// do runs fn with the thread's filesystem identity set to the owner. Permission checks then
// behave as if the owner did the work. When already not root, there is nothing to switch.
func (w Who) do(fn func() error) error {
	if os.Geteuid() != 0 || w.UID == 0 {
		return fn()
	}
	runtime.LockOSThread()
	prevU, _, _ := syscall.RawSyscall(syscall.SYS_SETFSUID, uintptr(w.UID), 0, 0)
	prevG, _, _ := syscall.RawSyscall(syscall.SYS_SETFSGID, uintptr(w.GID), 0, 0)
	// A second call with -1 returns the current value: check the switch took effect.
	nowU, _, _ := syscall.RawSyscall(syscall.SYS_SETFSUID, ^uintptr(0), 0, 0)
	err := errors.New("could not act as the owner of this home")
	if int(nowU) == w.UID {
		err = fn()
	}
	syscall.RawSyscall(syscall.SYS_SETFSUID, prevU, 0, 0)
	syscall.RawSyscall(syscall.SYS_SETFSGID, prevG, 0, 0)
	back, _, _ := syscall.RawSyscall(syscall.SYS_SETFSUID, ^uintptr(0), 0, 0)
	if back == prevU {
		runtime.UnlockOSThread() // otherwise the thread ends with this goroutine, still locked
	}
	return err
}
