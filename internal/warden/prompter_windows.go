//go:build windows

package warden

import (
	"context"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	toast "git.sr.ht/~jackmordaunt/go-toast/v2"
	"git.sr.ht/~jackmordaunt/go-toast/v2/wintoast"
)

// The toast uses the Windows Runtime directly (git.sr.ht/~jackmordaunt/go-toast/v2, pinned in
// go.mod): no PowerShell for the toast itself. Button clicks come back through the library's
// COM activation callback, as "warden|<id>|<decision>" (see ToastArgs).
const (
	toastAppID = "Manar.Warden"
	toastGUID  = "{6E1C0A52-3A0B-4C5E-9B6F-2D7A9C3F5B11}"
)

type toastPrompter struct {
	mu      sync.Mutex
	waiters map[string]chan Decision
}

func NewPrompter() (Prompter, error) {
	exe, _ := os.Executable()
	if err := toast.SetAppData(toast.AppData{AppID: toastAppID, GUID: toastGUID, ActivationExe: exe}); err != nil {
		return nil, err
	}
	p := &toastPrompter{waiters: map[string]chan Decision{}}
	toast.SetActivationCallback(func(args string, _ []toast.UserData) {
		id, d, ok := ParseToastArgs(args)
		if !ok {
			return
		}
		p.mu.Lock()
		ch := p.waiters[id]
		p.mu.Unlock()
		if ch != nil {
			select {
			case ch <- d:
			default:
			}
		}
	})
	return p, nil
}

func (p *toastPrompter) Show(ctx context.Context, pr Prompt, t Text) (Decision, error) {
	xml, err := BuildToastXML(toastAppID, pr, t)
	if err != nil {
		return "", err
	}
	ch := make(chan Decision, 1)
	p.mu.Lock()
	p.waiters[pr.ID] = ch
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.waiters, pr.ID)
		p.mu.Unlock()
	}()
	// No PowerShell fallback: if the Windows Runtime cannot show it, nothing is shown, the approval
	// stays pending and is decided in the console or on the phone.
	if err := wintoast.Push(toastAppID, xml); err != nil {
		return "", err
	}
	if pr.ConsoleOnly {
		return Dismissed, nil
	}
	select {
	case d := <-ch:
		return d, nil
	case <-time.After(10 * time.Minute):
		return Dismissed, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// SystemLang picks the prompt language from the user's Windows locale.
func SystemLang() Lang {
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetUserDefaultLocaleName")
	buf := make([]uint16, 85)
	r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if r == 0 {
		return EN
	}
	return LangFromLocale(syscall.UTF16ToString(buf))
}
