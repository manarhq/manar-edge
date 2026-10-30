package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// Entry is the manifest of one vaulted secret. It holds no secret.
type Entry struct {
	ID           string    `json:"id"`
	Kind         string    `json:"kind"` // aws | ssh
	Ref          string    `json:"ref"`
	File         FileInfo  `json:"file"`
	OrigSHA      string    `json:"origSha"`
	RewrittenSHA string    `json:"rewrittenSha,omitempty"` // aws: the file as Manar left it
	Fingerprint  string    `json:"fingerprint,omitempty"`  // ssh: key fingerprint held by the agent
	StoredAt     time.Time `json:"storedAt"`
}

// Vault moves secrets in and out of the store.
type Vault struct {
	Store Store
	// Exe is the path written into credential_process.
	Exe   string
	Agent Agent // ssh; nil where unsupported
	Homes func() []string
}

var (
	// ErrExists is returned when the secret is already in the vault.
	ErrExists = errors.New("already in the vault")
	// ErrNoSuchSecret is returned when no file holds the profile or key.
	ErrNoSuchSecret = errors.New("no such secret on this computer")
)

func idOf(kind, ref string) string { return kind + "-" + sum([]byte(kind + "/" + ref))[:16] }

var (
	sectionRe = regexp.MustCompile(`^\s*\[([^\]]+)\]\s*(?:[#;].*)?$`)
	keyRe     = regexp.MustCompile(`(?i)^\s*(aws_access_key_id|aws_secret_access_key|aws_session_token)\s*=\s*(.*?)\s*$`)
	profileRe = regexp.MustCompile(`^[A-Za-z0-9._@:+/-]{1,128}$`)
)

const marker = "# manar-vault: this profile's keys are held by Manar (manar-edge secret aws)"

// awsProfile finds the profile's key lines. It returns the line index of each key line.
func awsProfile(lines []string, profile string) (idx []int, vals map[string]string, hasProcess bool) {
	vals = map[string]string{}
	in := false
	for i, l := range lines {
		if m := sectionRe.FindStringSubmatch(l); m != nil {
			in = strings.TrimSpace(m[1]) == profile
			continue
		}
		if !in {
			continue
		}
		if m := keyRe.FindStringSubmatch(l); m != nil {
			idx = append(idx, i)
			vals[strings.ToLower(m[1])] = m[2]
		} else if strings.HasPrefix(strings.ToLower(strings.TrimSpace(l)), "credential_process") {
			hasProcess = true
		}
	}
	return
}

func splitLines(b []byte) (lines []string, eol string) {
	eol = "\n"
	if bytes.Contains(b, []byte("\r\n")) {
		eol = "\r\n"
	}
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	return strings.Split(s, "\n"), eol
}

func (v *Vault) processLine(profile string) string {
	exe := v.Exe
	if runtime.GOOS == "windows" {
		exe = filepath.ToSlash(exe)
	}
	return fmt.Sprintf(`credential_process = "%s" secret aws %s`, exe, profile)
}

// findCredentials locates the credentials file that holds the profile's keys.
func (v *Vault) findCredentials(profile string) (path string, data []byte, err error) {
	for _, h := range v.Homes() {
		p := filepath.Join(h, ".aws", "credentials")
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		lines, _ := splitLines(b)
		if _, vals, _ := awsProfile(lines, profile); vals["aws_access_key_id"] != "" && vals["aws_secret_access_key"] != "" {
			return p, b, nil
		}
	}
	return "", nil, ErrNoSuchSecret
}

// StoreAWS moves the profile's keys into the vault and replaces them in the file with a
// credential_process entry. The original is not touched until the vault copy reads back
// identically.
func (v *Vault) StoreAWS(profile string) (*Entry, error) {
	if !profileRe.MatchString(profile) {
		return nil, errors.New("bad profile name")
	}
	id := idOf("aws", profile)
	if _, err := v.Store.Get("m-" + id); err == nil {
		return nil, ErrExists
	}
	path, orig, err := v.findCredentials(profile)
	if err != nil {
		return nil, err
	}
	lines, eol := splitLines(orig)
	idx, vals, hasProc := awsProfile(lines, profile)
	if hasProc {
		return nil, errors.New("this profile already uses credential_process")
	}
	_, fi, err := readFile(path)
	if err != nil {
		return nil, err
	}
	secret, _ := json.Marshal(map[string]any{
		"Version": 1, "AccessKeyId": vals["aws_access_key_id"], "SecretAccessKey": vals["aws_secret_access_key"],
		"SessionToken": vals["aws_session_token"],
	})
	// The rewritten file: key lines out, marker and credential_process in at the first key line.
	var out []string
	for i, l := range lines {
		switch {
		case i == idx[0]:
			out = append(out, marker, v.processLine(profile))
		case contains(idx, i):
		default:
			out = append(out, l)
		}
	}
	rewritten := []byte(strings.Join(out, eol))
	if bytes.Contains(rewritten, []byte(vals["aws_secret_access_key"])) {
		return nil, errors.New("the rewritten file would still hold the secret")
	}
	e := &Entry{ID: id, Kind: "aws", Ref: profile, File: fi, OrigSHA: sum(orig), RewrittenSHA: sum(rewritten), StoredAt: time.Now().UTC()}
	if err := v.put(id, e, orig, secret); err != nil {
		return nil, err
	}
	if err := writeFile(fi, rewritten); err != nil {
		v.drop(id)
		return nil, fmt.Errorf("rewriting the credentials file: %w", err)
	}
	if got, _, err := readFile(path); err != nil || !bytes.Equal(got, rewritten) {
		_ = writeFile(fi, orig) // put it back before anything else
		v.drop(id)
		return nil, errors.New("the credentials file did not read back as written: restored")
	}
	return e, nil
}

func contains(s []int, x int) bool {
	for _, y := range s {
		if y == x {
			return true
		}
	}
	return false
}

// put writes the manifest, the original bytes and the secret, then reads all three back and
// compares. It fails (and removes what it wrote) unless every byte came back identical.
func (v *Vault) put(id string, e *Entry, orig, secret []byte) error {
	manifest, _ := json.Marshal(e)
	items := []struct {
		name string
		data []byte
	}{{"o-" + id, orig}, {"s-" + id, secret}, {"m-" + id, manifest}}
	for _, it := range items {
		if err := v.Store.Put(it.name, it.data); err != nil {
			v.drop(id)
			return fmt.Errorf("writing the vault: %w", err)
		}
	}
	for _, it := range items {
		got, err := v.Store.Get(it.name)
		if err != nil || !bytes.Equal(got, it.data) {
			v.drop(id)
			return errors.New("the vault copy did not read back identically: nothing was changed")
		}
	}
	return nil
}

func (v *Vault) drop(id string) {
	for _, p := range []string{"m-", "s-", "o-"} {
		_ = v.Store.Delete(p + id)
	}
}

// Entry loads a manifest.
func (v *Vault) Entry(kind, ref string) (*Entry, error) {
	b, err := v.Store.Get("m-" + idOf(kind, ref))
	if err != nil {
		return nil, err
	}
	var e Entry
	return &e, json.Unmarshal(b, &e)
}

// Entries lists everything in the vault.
func (v *Vault) Entries() ([]*Entry, error) {
	names, err := v.Store.List()
	if err != nil {
		return nil, err
	}
	var out []*Entry
	for _, n := range names {
		if !strings.HasPrefix(n, "m-") {
			continue
		}
		b, err := v.Store.Get(n)
		if err != nil {
			return out, err
		}
		var e Entry
		if err := json.Unmarshal(b, &e); err != nil {
			return out, err
		}
		out = append(out, &e)
	}
	return out, nil
}

// AWSCredentialProcess returns the JSON a credential_process prints for the profile.
func (v *Vault) AWSCredentialProcess(profile string) ([]byte, error) {
	return v.Store.Get("s-" + idOf("aws", profile))
}

// RestoreAWS puts the profile's keys back in the file. When the file is as Manar left it, the
// original bytes and permissions come back exactly; when the person edited it since, only
// Manar's lines are swapped for the original key lines.
func (v *Vault) RestoreAWS(profile string) error {
	e, err := v.Entry("aws", profile)
	if err != nil {
		return err
	}
	orig, err := v.Store.Get("o-" + e.ID)
	if err != nil {
		return fmt.Errorf("the vault has no original for this profile: %w", err)
	}
	cur, _, rerr := readFile(e.File.Path)
	switch {
	case rerr != nil: // file removed meanwhile
		_ = os.MkdirAll(filepath.Dir(e.File.Path), 0o700)
		err = writeFile(e.File, orig)
	case sum(cur) == e.OrigSHA:
		err = nil
	case sum(cur) == e.RewrittenSHA:
		err = writeFile(e.File, orig)
	default:
		err = v.swapBack(e, cur, orig)
	}
	if err != nil {
		return err
	}
	// Verify before the vault forgets: the keys are in the file again.
	got, _, err := readFile(e.File.Path)
	if err != nil || !restored(got, orig, profile) {
		return errors.New("the file does not hold the keys after restore: the vault copy is kept")
	}
	v.drop(e.ID)
	return nil
}

func restored(got, orig []byte, profile string) bool {
	gl, _ := splitLines(got)
	ol, _ := splitLines(orig)
	_, gv, gp := awsProfile(gl, profile)
	_, ov, _ := awsProfile(ol, profile)
	return !gp && gv["aws_access_key_id"] == ov["aws_access_key_id"] && gv["aws_secret_access_key"] == ov["aws_secret_access_key"] &&
		gv["aws_session_token"] == ov["aws_session_token"]
}

func (v *Vault) swapBack(e *Entry, cur, orig []byte) error {
	ol, _ := splitLines(orig)
	oidx, _, _ := awsProfile(ol, e.Ref)
	var keyLines []string
	for _, i := range oidx {
		keyLines = append(keyLines, ol[i])
	}
	cl, eol := splitLines(cur)
	var out []string
	done := false
	for i := 0; i < len(cl); i++ {
		if cl[i] == marker && i+1 < len(cl) && strings.HasPrefix(cl[i+1], "credential_process") && strings.Contains(cl[i+1], " secret aws ") {
			out = append(out, keyLines...)
			i++
			done = true
			continue
		}
		out = append(out, cl[i])
	}
	if !done {
		return errors.New("Manar's lines are no longer in the credentials file: edit it by hand; the vault copy is kept")
	}
	return writeFile(e.File, []byte(strings.Join(out, eol)))
}
