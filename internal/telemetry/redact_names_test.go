package telemetry

import "testing"

func TestScrubNamesReplacesTheLongerNameFirst(t *testing.T) {
	for _, c := range []struct{ user, host, in, want string }{
		{"lab", "agent-lab", "ssh agent-lab uptime", "ssh <host> uptime"},
		{"lab", "agent-lab", "lab@agent-lab", "<user>@<host>"},
		{"sam-pc-long", "sam", "sam-pc-long on sam", "<user> on <host>"},
	} {
		if got := scrubNames(c.in, c.user, c.host); got != c.want {
			t.Errorf("%q (user %s, host %s) = %q, want %q", c.in, c.user, c.host, got, c.want)
		}
	}
}
