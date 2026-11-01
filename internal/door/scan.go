package door

import (
	"regexp"
	"sort"
	"strings"
)

// Detectors are deterministic regular expressions, never a model. They run on the raw JSON text of
// a request body, so a match never contains a quote or backslash that would break the JSON when it
// is replaced by a mask (the private key pattern skips escapes as whole units for the same reason).
type detector struct {
	kind string
	re   *regexp.Regexp
	// group is the capture group holding the secret itself (0 = the whole match).
	group int
}

const jsonStr = `(?:[^"\\]|\\.)*`

var detectors = []detector{
	{"private_key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----(?:` + jsonStr + `?-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|` + jsonStr + `)`), 0},
	{"aws_access_key", regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b`), 0},
	{"anthropic_key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}`), 0},
	{"openai_key", regexp.MustCompile(`\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}`), 0},
	{"github_token", regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})`), 0},
	{"gitlab_token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}`), 0},
	{"google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), 0},
	{"slack_token", regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`), 0},
	{"stripe_key", regexp.MustCompile(`\b[sr]k_live_[A-Za-z0-9]{16,}`), 0},
	{"npm_token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), 0},
	{"pypi_token", regexp.MustCompile(`\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{40,}`), 0},
	// password = value, "password": "value", API_KEY=value. The value excludes quotes, backslashes and
	// whitespace, so replacing it keeps the JSON valid; placeholders are skipped in isPlaceholder.
	{"password", regexp.MustCompile(`(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b(?:\\?["'])?\s*[:=]\s*(?:\\?["'])?([^\s"'\\,;]{8,})`), 1},
}

// Finding is one secret found: its kind and a masked sample (first characters, then ****).
type Finding struct {
	Kind   string
	Sample string
}

type span struct {
	start, end int
	kind       string
}

func isPlaceholder(v string) bool {
	l := strings.ToLower(v)
	for _, p := range []string{"<", "${", "{{", "$(", "%s", "xxxx", "****", "....", "your", "example", "changeme", "placeholder", "process.env", "os.environ", "env[", "null", "none", "true", "false", "undefined"} {
		if strings.Contains(l, p) {
			return true
		}
	}
	// A value made of one repeated character is not a credential.
	return strings.Trim(l, string(l[0])) == ""
}

// maskSample keeps at most four leading characters (and fewer for short values).
func maskSample(v string) string {
	n := len(v) / 4
	if n > 4 {
		n = 4
	}
	return v[:n] + "****"
}

// Scan returns the secrets in body, and body with each replaced by [MANAR-MASKED:kind]. Matches
// that overlap are merged, the earliest kind winning.
func Scan(body []byte) ([]Finding, []byte) {
	var spans []span
	var found []Finding
	for _, d := range detectors {
		for _, m := range d.re.FindAllSubmatchIndex(body, -1) {
			s, e := m[2*d.group], m[2*d.group+1]
			if s < 0 {
				continue
			}
			v := string(body[s:e])
			if d.kind == "password" && isPlaceholder(v) {
				continue
			}
			spans = append(spans, span{s, e, d.kind})
		}
	}
	if len(spans) == 0 {
		return nil, body
	}
	sort.SliceStable(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	var out []byte
	pos := 0
	for _, sp := range spans {
		if sp.start < pos { // inside a span already masked
			continue
		}
		out = append(out, body[pos:sp.start]...)
		out = append(out, "[MANAR-MASKED:"+sp.kind+"]"...)
		found = append(found, Finding{sp.kind, maskSample(string(body[sp.start:sp.end]))})
		pos = sp.end
	}
	if len(found) == 0 {
		return nil, body
	}
	return found, append(out, body[pos:]...)
}
