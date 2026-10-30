package host

import "testing"

func TestMaskPath(t *testing.T) {
	homes := []string{"/home/alice", `C:\Users\Bob`}
	for in, want := range map[string]string{
		"/home/alice/.aws/credentials":        "~/.aws/credentials",
		`C:\Users\Bob\.ssh\id_ed25519`:        "~/.ssh/id_ed25519",
		`c:\users\bob\.ssh\id_ed25519`:        "~/.ssh/id_ed25519",
		"/home/carol/.kube/config":            "~/.kube/config",
		"/root/.aws/credentials":              "~/.aws/credentials",
		"/home/alice":                         "~",
		"/home/alicebob/x":                    "~/x",
		"/srv/app/.env":                       "/srv/app/.env",
		"/home/alice/work/../../bob/.ssh/key": "~/work/../../bob/.ssh/key",
	} {
		if got := MaskPath(homes, in); got != want {
			t.Errorf("MaskPath(%q) = %q, want %q", in, got, want)
		}
	}
}
