package telemetry

import (
	"os"
	"os/user"
	"strings"
	"testing"
)

// Secrets are assembled at run time so no scanner sees a literal key in the source.
var (
	awsKey    = "AK" + "IA" + "IOSFODNN7EXAMPLQ"
	jwt       = "eyJ" + "hbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0." + "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	pem       = "-----BEGIN RSA PRIVATE " + "KEY-----\nMIIEowIBAAKCAQEA7x9fK3\nabcdef0123456789\n-----END RSA PRIVATE " + "KEY-----"
	ghToken   = "gh" + "p_" + "aB3dE5gH7jK9mN1pQ3rS5tU7vW9xY1zA3bC5"
	antKey    = "sk-" + "ant-api03-" + "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Ji1"
	slack     = "xox" + "b-" + "123456789012-abcdefghijkl"
	bearerVal = "abcdefgh" + "12345678"
	hexLong   = "3f9a1c7e5b2d4a6f8c0e1b3d5f7a9c2e4b6d8f0a"
)

func TestRedactRules(t *testing.T) {
	home, _ := os.UserHomeDir()
	host, _ := os.Hostname()
	cases := []struct {
		name, in string
		want     string // substring that must appear
		absent   string // substring that must not appear
	}{
		{"home linux", "cat /home/alice/work/x.txt", "~/work/x.txt", "alice"},
		{"home mac style", "ls /Users/bob/src", "~/src", "bob"},
		{"home windows", `type C:\Users\Carol\Desktop\a.txt`, `~\Desktop\a.txt`, "Carol"},
		{"home dir literal", "ls " + home + "/proj", "~/proj", ""},
		{"email", "git config user.email jane.doe@example.com", "<email>", "jane.doe"},
		{"ipv4", "ssh root@10.20.30.40", "<ip>", "10.20.30.40"},
		{"ipv6", "ping 2001:db8:85a3::8a2e:370:7334", "<ip>", "2001:db8"},
		{"ipv6 loopback", "curl http://[::1]:8080/x", "<ip>", "::1"},
		{"version not ip", "tool 1.2.3", "1.2.3", ""},
		{"time not ip", "at 12:30:45", "12:30:45", ""},
		{"url query", "curl https://api.example.com/v1/items?page=2&x=1", "https://api.example.com/v1/items", "page=2"},
		{"url fragment", "open https://example.com/a#section-9", "https://example.com/a", "section-9"},
		{"url userinfo", "git clone https://user:hunter2hunter2@github.com/x/y.git", "https://github.com/x/y.git", "hunter2"},
		{"aws key", "export X=" + awsKey, redacted, awsKey},
		{"jwt", "curl -H 'X: " + jwt + "'", redacted, "eyJ"},
		{"private key", "echo '" + pem + "' > k", redacted, "MIIEow"},
		{"private key unterminated", "x " + pem[:60] + "\nMIIEowIBAAKCAQEA", redacted, "MIIEow"},
		{"github token", "git push https://" + ghToken + "@github.com/a/b", "", ghToken},
		{"anthropic key", "ANTHROPIC=" + antKey + " run", "", antKey},
		{"slack token", "post " + slack, redacted, slack},
		{"assignment secret name", "DB_PASSWORD=short run", "DB_PASSWORD=" + redacted, "short"},
		{"assignment api key quoted", `API_KEY="abc"`, "API_KEY=" + redacted, `"abc"`},
		{"assignment colon", "client_secret: abc", "client_secret: " + redacted, "abc"},
		{"password flag", "mysql --password hunter2 -u root", redacted, "hunter2"},
		{"token flag equals", "tool --api-token=abc123", redacted, "abc123"},
		{"bearer", "curl -H 'Authorization: Bearer " + bearerVal + "'", redacted, bearerVal},
		{"long hex", "checkout " + hexLong, redacted, hexLong},
		{"short word kept", "ls -la", "ls -la", ""},
		{"long path kept", "cd /usr/local/share/some/very/long/directory/name/here", "/usr/local/share/some/very/long/directory/name/here", ""},
	}
	if host != "" && len(host) >= 3 {
		cases = append(cases, struct{ name, in, want, absent string }{"host name", "ssh " + host + " uptime", "<host>", host})
	}
	if u, err := user.Current(); err == nil && len(u.Username) >= 3 {
		cases = append(cases, struct{ name, in, want, absent string }{"os user", "chown " + u.Username + " f", "<user>", u.Username})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Redact(c.in)
			if !strings.Contains(got, c.want) {
				t.Errorf("Redact(%q) = %q, want it to contain %q", c.in, got, c.want)
			}
			if c.absent != "" && strings.Contains(strings.ToLower(got), strings.ToLower(c.absent)) {
				t.Errorf("Redact(%q) = %q still contains %q", c.in, got, c.absent)
			}
		})
	}
}

func TestRedactMaxLength(t *testing.T) {
	got := Redact(strings.Repeat("ab cd ", 400))
	if n := len([]rune(got)); n != 512 {
		t.Fatalf("length %d, want 512", n)
	}
	// A secret that straddles the 512 cut is redacted before the cut, never left half visible.
	in := strings.Repeat("x", 500) + " token=" + strings.Repeat("Qz7", 20)
	if got := Redact(in); strings.Contains(got, "Qz7") {
		t.Fatalf("partial secret survived: %q", got)
	}
}

// The planted-secret test: each secret, in each wrapper, in the middle of ordinary text.
func TestPlantedSecretNeverSurvives(t *testing.T) {
	secrets := map[string]string{
		"aws": awsKey, "jwt": jwt, "github": ghToken, "anthropic": antKey,
		"pem body": "MIIEowIBAAKCAQEA7x9fK3", "slack": slack,
	}
	wrappers := []string{
		"%s", "echo %s", "X=%s run", "curl -H 'Authorization: Bearer %s'", "password=%s", `{"token": "%s"}`,
		"export AWS_SECRET_ACCESS_KEY=%s && ./go", "cmd --password %s --flag", "git push https://u:%s@h.io/r",
		"https://x.io/p?k=%s", "line1\nline2 %s\nline3", "a;b;%s;c", "SECRET_TOKEN='%s'",
	}
	for name, sec := range secrets {
		for _, w := range wrappers {
			in := strings.ReplaceAll(w, "%s", sec)
			if name == "pem body" {
				in = strings.ReplaceAll(w, "%s", pem)
			}
			got := Redact(in)
			for _, frag := range []string{sec[:min(len(sec), 12)], sec[max(0, len(sec)-12):]} {
				if strings.Contains(got, frag) {
					t.Errorf("%s in %q: %q survived in %q", name, w, frag, got)
				}
			}
		}
	}
	// A short password is only recognisable by its name (rule: KEY=value with a secret-looking name).
	for _, w := range []string{"password=%s", "DB_PASSWORD=%s run", "--password %s", `{"password": "%s"}`, "secret: %s", "TOKEN='%s'"} {
		got := Redact(strings.ReplaceAll(w, "%s", "Tr0ub4dor&3xKcd9"))
		if strings.Contains(got, "Tr0ub") || strings.Contains(got, "Kcd9") {
			t.Errorf("password in %q survived: %q", w, got)
		}
	}
	// A private key block keeps nothing of its body even when pasted with surrounding text.
	got := Redact("before " + pem + " after")
	if strings.Contains(got, "MIIEow") || strings.Contains(got, "abcdef0123") || !strings.Contains(got, "before") {
		t.Fatalf("unexpected: %q", got)
	}
}

// FuzzRedactPlanted plants a random-looking secret in random surroundings; none of it may survive.
func FuzzRedactPlanted(f *testing.F) {
	f.Add("echo ", " done", uint8(0))
	f.Add("a=b;", "\n", uint8(3))
	f.Fuzz(func(t *testing.T, pre, post string, which uint8) {
		secrets := []string{awsKey, jwt, ghToken, antKey, slack, "api_key=" + "Zq8" + "Lm2Xv9Rt4Bn7"}
		sec := secrets[int(which)%len(secrets)]
		// The surroundings must not themselves split the secret.
		if strings.ContainsAny(pre, "-_=") && strings.HasSuffix(pre, "-") {
			t.Skip()
		}
		got := Redact(pre + " " + sec + " " + post)
		frag := sec[len(sec)/2-5 : len(sec)/2+5]
		if strings.Contains(got, frag) {
			t.Fatalf("secret survived: %q", got)
		}
	})
}
