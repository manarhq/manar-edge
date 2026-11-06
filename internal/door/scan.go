package door

import (
	"bytes"
	"encoding/json"
	"math"
	"sort"
	"strings"

	"github.com/manarhq/manar-edge/internal/lazyre"
)

// Detectors are deterministic regular expressions, never a model. They run on the raw JSON text of
// a request body, so a match never contains a quote or backslash that would break the JSON when it
// is replaced by a mask (the private key pattern skips escapes as whole units for the same reason).
type detector struct {
	kind string
	re   *lazyre.Re
	// group is the capture group holding the secret itself (0 = the whole match).
	group int
	// accept, when set, vets the matched secret (placeholders, code, low entropy are refused).
	accept func(string) bool
}

const passKey = `(?i)(?:^|[^A-Za-z0-9])(?:[A-Za-z0-9]+[_-])*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b`

const jsonStr = `(?:[^"\\]|\\.)*`

var detectors = []detector{
	{"private_key", lazyre.New(`-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----(?:` + jsonStr + `?-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|` + jsonStr + `)`), 0, nil},
	{"aws_access_key", lazyre.New(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b`), 0, nil},
	{"anthropic_key", lazyre.New(`\bsk-ant-[A-Za-z0-9_-]{20,}`), 0, nil},
	{"openai_key", lazyre.New(`\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}`), 0, nil},
	{"github_token", lazyre.New(`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})`), 0, nil},
	{"gitlab_token", lazyre.New(`\bglpat-[A-Za-z0-9_-]{20,}`), 0, nil},
	{"google_api_key", lazyre.New(`\bAIza[0-9A-Za-z_-]{35}\b`), 0, nil},
	{"slack_token", lazyre.New(`\bxox[abprs]-[A-Za-z0-9-]{10,}`), 0, nil},
	{"stripe_key", lazyre.New(`\b[sr]k_live_[A-Za-z0-9]{16,}`), 0, nil},
	{"npm_token", lazyre.New(`\bnpm_[A-Za-z0-9]{36}\b`), 0, nil},
	{"pypi_token", lazyre.New(`\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{40,}`), 0, nil},
	// A key=value pair needs a literal value: either quoted, or unquoted and random-looking. Code
	// that reads a secret (getenv, settings.X, calls) and placeholders are not findings.
	{"password", lazyre.New(passKey + `["']?\s*[:=]\s*["']([^"'\s\\]{8,})["']`), 1, func(v string) bool { return acceptValue(v, 2.5) }},
	{"password", lazyre.New(passKey + `["']?\s*[:=]\s*([^\s"',;]{8,})`), 1, func(v string) bool { return acceptValue(v, 3.0) && classes(v) >= 2 }},
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

var (
	dottedIdent = lazyre.New(`^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$`)
	codeWords   = []string{"getenv", "environ", "settings", "config", "secrets.", "getpass", "input(", "prompt", "self.", "this.", "args.", "params."}
)

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

func entropy(v string) float64 {
	n := map[rune]int{}
	for _, r := range v {
		n[r]++
	}
	var h, total float64 = 0, float64(len([]rune(v)))
	for _, c := range n {
		p := float64(c) / total
		h -= p * math.Log2(p)
	}
	return h
}

// classes counts how many of lower, upper, digit and symbol the value uses.
func classes(v string) int {
	var lo, up, di, sy bool
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
			lo = true
		case r >= 'A' && r <= 'Z':
			up = true
		case r >= '0' && r <= '9':
			di = true
		default:
			sy = true
		}
	}
	n := 0
	for _, b := range []bool{lo, up, di, sy} {
		if b {
			n++
		}
	}
	return n
}

// acceptValue refuses placeholders and values that read like code (identifiers, calls, environment
// lookups); the rest must look random enough (Shannon entropy in bits per character).
func acceptValue(v string, minEntropy float64) bool {
	if isPlaceholder(v) || dottedIdent.MatchString(v) || strings.ContainsAny(v, "()[]{}<>$") {
		return false
	}
	l := strings.ToLower(v)
	for _, w := range codeWords {
		if strings.Contains(l, w) {
			return false
		}
	}
	return entropy(v) >= minEntropy
}

// maskSample keeps at most four leading characters (and fewer for short values).
func maskSample(v string) string {
	n := len(v) / 4
	if n > 4 {
		n = 4
	}
	return v[:n] + "****"
}

// Scan returns the secrets in text, and text with each replaced by [MANAR-MASKED:kind]. Matches
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
			if d.accept != nil && !d.accept(v) {
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

// ScanBody scans a request body. A JSON body is parsed and every decoded string value is scanned,
// so \u0041KIA... escapes do not hide a key; the body is only re-encoded when something was
// masked, otherwise the original bytes go on untouched. Anything that is not one JSON value is
// scanned as plain text. This catches keys and passwords pasted by accident; it does not decode
// base64 or find a secret split across fields.
func ScanBody(body []byte) ([]Finding, []byte) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil || dec.More() {
		return Scan(body)
	}
	var found []Finding
	var walk func(any) any
	walk = func(x any) any {
		switch t := x.(type) {
		case string:
			if f, out := Scan([]byte(t)); len(f) > 0 {
				found = append(found, f...)
				return string(out)
			}
		case map[string]any:
			for k, e := range t {
				t[k] = walk(e)
			}
		case []any:
			for i, e := range t {
				t[i] = walk(e)
			}
		}
		return x
	}
	v = walk(v)
	if len(found) == 0 {
		return nil, body
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return found, nil // cannot happen for decoded JSON; callers treat nil as a refusal
	}
	return found, bytes.TrimRight(buf.Bytes(), "\n")
}
