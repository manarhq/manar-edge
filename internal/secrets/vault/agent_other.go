//go:build !windows

package vault

// Linux: the user agent run by Manar with confirm-on-use is not built yet, so the ssh half of
// the vault reports that it is unavailable here.
func platformAgent() Agent { return nil }

func ensureAgent() {}
