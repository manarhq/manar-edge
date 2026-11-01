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
		"password":       `password: Xk9#mQ2vLp8zR`,
	}
	for kind, secret := range cases {
		body := []byte(`{"messages":[{"role":"user","content":"please use ` + secret + ` for the call"}]}`)
		f, out := ScanBody(body)
		if len(f) != 1 || f[0].Kind != kind {
			t.Fatalf("%s: findings %+v", kind, f)
		}
		if !json.Valid(out) {
			t.Fatalf("%s: masked body is not valid JSON: %s", kind, out)
		}
		if strings.Contains(string(out), strings.TrimPrefix(secret, "password: ")) && kind != "password" || strings.Contains(string(out), "Xk9#mQ2vLp8zR") {
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
		`{"content":"password = os.getenv(\"DB_PASSWORD\") and api_key = settings.OPENAI_KEY"}`,
		`{"content":"secret: request.form[\"secret\"]; token = get_token(user)"}`,
		`{"content":"password: hunter2hunter2 is weak"}`, // low entropy unquoted: not a finding
		`{"content":"API_KEY=aaaaaaaaaaaa"}`,
	} {
		if f, out := ScanBody([]byte(s)); len(f) != 0 || string(out) != s {
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

func TestScanSeesThroughJSONEscapes(t *testing.T) {
	// \u0041KIA... is AKIA... once decoded; a plain-text scan of the raw bytes would miss it.
	body := `{"messages":[{"content":"use \u0041KIAIOSFODNN7EXAMPLE and \"password\": \"hunter2hunter2\""}],"n":1.50,"stream":true}`
	f, out := ScanBody([]byte(body))
	if len(f) != 2 || !json.Valid(out) {
		t.Fatalf("%+v %s", f, out)
	}
	if strings.Contains(string(out), "AKIA") || strings.Contains(string(out), "hunter2") || !strings.Contains(string(out), `"n":1.50`) {
		t.Fatalf("%s", out)
	}
	// Clean JSON is forwarded byte for byte.
	clean := `{ "a" : "hello",  "b":[1, 2] }`
	if f, out := ScanBody([]byte(clean)); len(f) != 0 || string(out) != clean {
		t.Fatal("clean body changed")
	}
}

func TestPrefixedKeyNamesAndQuotedValues(t *testing.T) {
	for _, s := range []string{`DB_PASSWORD=Xk9#mQ2vLp8zR`, `{"api_key": "a1B2c3D4e5F6"}`, `OPENAI_API_KEY='zZ9yY8xX7wW6'`} {
		if f, _ := ScanBody([]byte(`{"c":` + mustJSON(s) + `}`)); len(f) != 1 {
			t.Errorf("missed %s: %+v", s, f)
		}
	}
}

func mustJSON(s string) string { b, _ := json.Marshal(s); return string(b) }
