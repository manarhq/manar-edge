package telemetry

import (
	"math"
	"net/netip"
	"net/url"
	"os"
	"os/user"
	"regexp"
	"strings"
	"unicode/utf8"

	"gitlab.vax.sh/manar/manar-edge/internal/door"
)

// maxSample is the longest sample after redaction (design spec section 1).
const maxSample = 512

// maxRedactInput bounds the work: the whole text is redacted before it is cut to maxSample, so a
// secret that straddles the cut is never left half visible.
const maxRedactInput = 64 << 10

const redacted = "<redacted>"

var (
	reURL      = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s"'<>` + "`" + `]+`)
	reMask     = regexp.MustCompile(`\[MANAR-MASKED:[a-z_]+\]`)
	reJWT      = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*`)
	reBearer   = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`)
	rePEM      = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)`)
	reAssign   = regexp.MustCompile(`(?i)\b([A-Za-z0-9_.-]*(?:secret|token|passw(?:or)?d|passwd|pwd|api[_-]?key|private[_-]?key|credential|auth)[A-Za-z0-9_.-]*)(\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s"',;&]+)`)
	reFlag     = regexp.MustCompile(`(?i)(--?(?:[a-z0-9-]*(?:secret|token|passw(?:or)?d|pass|pwd|api-?key|credential)[a-z0-9-]*)[ =]+)("[^"]*"|'[^']*'|[^\s"']+)`)
	reEmail    = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+`)
	reIPv4     = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reIPv6     = regexp.MustCompile(`[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*`)
	reHomeUnix = regexp.MustCompile(`/(?:home|Users)/[^/\s"'\\:]+`)
	reHomeWin  = regexp.MustCompile(`(?i)[A-Z]:[\\/]+Users[\\/]+[^\\/\s"':]+`)
	reLong     = regexp.MustCompile(`[A-Za-z0-9+/_=-]{32,}`)
)

// Redact removes what must never leave the device from a command or domain sample, in the order
// of design spec section 1, and cuts the result to 512 characters.
func Redact(s string) string { return cut(scrubPaths(redactSecrets(s)), maxSample) }

func cut(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

func redactSecrets(s string) string {
	if len(s) > maxRedactInput {
		s = s[:maxRedactInput]
	}
	s = strings.ToValidUTF8(s, "")
	// Keys and JWTs first: URL stripping could cut the start of one off and hide it from them.
	s = rePEM.ReplaceAllString(s, redacted)
	s = reJWT.ReplaceAllString(s, redacted)
	s = reURL.ReplaceAllStringFunc(s, stripURL)
	// The patterns the edge already uses to mask keys sent to AI providers (DOOR).
	if f, out := door.Scan([]byte(s)); len(f) > 0 {
		s = string(out)
	}
	s = reMask.ReplaceAllString(s, redacted)
	s = reBearer.ReplaceAllString(s, "$1 "+redacted)
	s = reFlag.ReplaceAllString(s, "${1}"+redacted)
	s = reAssign.ReplaceAllString(s, "${1}${2}"+redacted)
	s = reIPv4.ReplaceAllStringFunc(s, func(m string) string {
		if _, err := netip.ParseAddr(m); err != nil {
			return m
		}
		return "<ip>"
	})
	s = reIPv6.ReplaceAllStringFunc(s, func(m string) string {
		if a, err := netip.ParseAddr(strings.Trim(m, ".")); err != nil || !a.Is6() {
			return m
		}
		return "<ip>"
	})
	s = reEmail.ReplaceAllString(s, "<email>")
	return reLong.ReplaceAllStringFunc(s, func(m string) string {
		if looksRandom(m) {
			return redacted
		}
		return m
	})
}

// stripURL drops user:password@, the query string and the fragment.
func stripURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		if i := strings.IndexAny(raw, "?#"); i >= 0 {
			raw = raw[:i]
		}
		if i := strings.Index(raw, "://"); i >= 0 {
			if j := strings.LastIndex(raw[i+3:], "@"); j >= 0 {
				raw = raw[:i+3] + raw[i+3+j+1:]
			}
		}
		return raw
	}
	u.User, u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment = nil, "", false, "", ""
	return u.String()
}

// looksRandom: 32+ characters with high Shannon entropy. A path-like run (several slashes) must
// also mix upper case, lower case and digits, so long file paths survive.
func looksRandom(v string) bool {
	h := entropy(v)
	var lo, up, di bool
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
			lo = true
		case r >= 'A' && r <= 'Z':
			up = true
		case r >= '0' && r <= '9':
			di = true
		}
	}
	n := 0
	for _, b := range []bool{lo, up, di} {
		if b {
			n++
		}
	}
	if strings.Count(v, "/") >= 2 {
		return n == 3 && h >= 4.0
	}
	return n >= 2 && h >= 3.5
}

func entropy(v string) float64 {
	cnt := map[rune]float64{}
	for _, r := range v {
		cnt[r]++
	}
	total := float64(utf8.RuneCountInString(v))
	var h float64
	for _, c := range cnt {
		p := c / total
		h -= p * math.Log2(p)
	}
	return h
}

// scrubPaths: home directories to ~, then the OS user name and the host name.
func scrubPaths(s string) string {
	s = reHomeUnix.ReplaceAllString(s, "~")
	s = reHomeWin.ReplaceAllString(s, "~")
	if h, err := os.UserHomeDir(); err == nil && len(h) > 1 {
		s = strings.ReplaceAll(s, h, "~")
	}
	if u, err := user.Current(); err == nil {
		name := u.Username
		if i := strings.LastIndex(name, `\`); i >= 0 {
			name = name[i+1:]
		}
		s = replaceWord(s, name, "<user>")
	}
	if h, err := os.Hostname(); err == nil {
		s = replaceWord(s, h, "<host>")
	}
	return s
}

// replaceWord replaces name where it is not part of a longer word. Names under 3 characters
// would damage ordinary text, so they are skipped.
func replaceWord(s, name, with string) string {
	if len(name) < 3 {
		return s
	}
	return regexp.MustCompile(`(?i)(^|[^A-Za-z0-9])`+regexp.QuoteMeta(name)+`($|[^A-Za-z0-9])`).
		ReplaceAllString(s, "${1}"+with+"${2}")
}
