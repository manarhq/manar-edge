//go:build linux

package watch

import "gitlab.vax.sh/manar/manar-edge/internal/secrets/vault"

// The ssh agent asks the watcher's catalogue who is behind a sign request: an AI tool's own
// non-interactive chain needs the person's yes; the person's own terminal does not.
func init() {
	procs := newProcSource()
	vault.AIChain = func(pid int) (int, bool) {
		a := Attribute(procs, pid)
		if a.ToolID == "" || a.Interactive {
			return 0, false
		}
		return a.ToolProc.PID, true
	}
}
