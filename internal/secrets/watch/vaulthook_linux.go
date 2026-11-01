//go:build linux

package watch

import "gitlab.vax.sh/manar/manar-edge/internal/secrets/vault"

// The ssh agent and the restore command ask the watcher's catalogue who is behind a request.
// Only blockable AI tools count (the same rule as the file block): an editor's own git push is the
// person's, and a shell that looks interactive below a blockable tool gets no exemption.
func init() {
	procs := newProcSource()
	vault.SetAIChain(func(pid int) (int, bool) {
		a := Attribute(procsWithTaint(procs), pid)
		if a.ToolID == "" || !a.Block {
			return 0, false
		}
		return a.ToolProc.PID, true
	})
}
