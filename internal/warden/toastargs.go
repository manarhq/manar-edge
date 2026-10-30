package warden

import "strings"

// Toast buttons carry "warden|<prompt id>|<decision>" as their activation arguments. The Windows
// callback gives that string back; ParseToastArgs turns it into an answer. It is separate from the
// Windows code so the mapping is tested everywhere.
func ToastArgs(id string, d Decision) string { return "warden|" + id + "|" + string(d) }

func ParseToastArgs(args string) (id string, d Decision, ok bool) {
	parts := strings.Split(args, "|")
	if len(parts) != 3 || parts[0] != "warden" || parts[1] == "" {
		return "", "", false
	}
	d = Decision(parts[2])
	if d != ApproveOnce && d != Deny {
		return "", "", false
	}
	return parts[1], d, true
}
