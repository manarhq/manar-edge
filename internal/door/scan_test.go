package door

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestScanFindsAndMasks(t *testing.T) {
	pk := `-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\nAAAA\n-----END OPENSSH PRIVATE KEY-----`
	cases := map[string]string{
		"aws_access_key": `AKIAIOSFODNN7EXAMPLE`,
		"github_token":   `ghp_` + strings.Repeat("a1B2", 9),
		"anthropic_key":  `sk-ant-api03-` + strings.Repeat("Zz9_", 8),
		"openai_key":     `sk-proj-` + strings.Repeat("Ab3d", 10),
		"google_api_key": `AIza` + strings.Repeat("x9Y_", 8) + `abc`,
		"private_key":    pk,
		"password":       `password: hunter2hunter2`,
	}
	for kind, secret := range cases {
		body := []byte(`{"messages":[{"role":"user","content":"please use ` + secret + ` for the call"}]}`)
		f, out := Scan(body)
		if len(f) != 1 || f[0].Kind != kind {
			t.Fatalf("%s: findings %+v", kind, f)
		}
		if !json.Valid(out) {
			t.Fatalf("%s: masked body is not valid JSON: %s", kind, out)
		}
		if strings.Contains(string(out), strings.TrimPrefix(secret, "password: ")) && kind != "password" || strings.Contains(string(out), "hunter2hunter2") {
			t.Fatalf("%s: secret left in %s", kind, out)
		}
		if !strings.Contains(string(out), "[MANAR-MASKED:"+kind+"]") || strings.Contains(f[0].Sample, secret) {
			t.Fatalf("%s: mask or sample wrong: %s %q", kind, out, f[0].Sample)
		}
	}
}

func TestScanLeavesPlainAndPlaceholders(t *testing.T) {
	for _, s := range []string{
		`{"content":"hello, explain password hashing"}`,
		`{"content":"set password = <your-password> in the config"}`,
		`{"content":"API_KEY=${API_KEY} and secret: xxxxxxxx"}`,
		`{"content":"token: process.env.TOKEN_VALUE"}`,
		`{"content":"the key sk-short is too short"}`,
	} {
		if f, out := Scan([]byte(s)); len(f) != 0 || string(out) != s {
			t.Fatalf("false positive on %s: %+v", s, f)
		}
	}
}

func TestScanUnterminatedPrivateKeyMasksToEndOfString(t *testing.T) {
	body := `{"c":"-----BEGIN RSA PRIVATE KEY-----\nMIIEow","d":"after"}`
	f, out := Scan([]byte(body))
	if len(f) != 1 || !json.Valid(out) || !strings.Contains(string(out), `"d":"after"`) {
		t.Fatalf("%+v %s", f, out)
	}
}
