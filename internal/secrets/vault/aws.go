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
	Owner        string    `json:"owner"` // Who.Key() of the home's owner
	UID          int       `json:"uid"`
	GID          int       `json:"gid"`
	Home         string    `json:"home"`
	File         FileInfo  `json:"file"`
	Line         string    `json:"line,omitempty"` // aws: the exact credential_process line written
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
	Agent Agent // ssh (Windows OpenSSH agent); nil where unsupported
	// Keys is Manar's own ssh agent keyring (Linux). When set, ssh keys go there, not to Agent.
	Keys  *Keyring
	Homes func() []string
}

var (
	// ErrExists is returned when the secret is already in the vault.
	ErrExists = errors.New("already in the vault")
	// ErrNoSuchSecret is returned when no file holds the profile or key.
	ErrNoSuchSecret = errors.New("no such secret on this computer")
	// ErrAmbiguous is returned when more than one user has the same profile or key name; Manar
	// will not guess whose it is.
	ErrAmbiguous = errors.New("more than one user on this computer has that name")
)

func idOf(kind, ref, owner string) string {
	return kind + "-" + sum([]byte(kind + "\x00" + ref + "\x00" + owner))[:16]
}

func (e *Entry) who() Who { return Who{UID: e.UID, GID: e.GID, SID: sidOf(e.Owner)} }

func sidOf(owner string) string {
	if strings.HasPrefix(owner, "S-") {
		return owner
	}
	return ""
}

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

// findCredentials locates the one credentials file that holds the profile's keys.
func (v *Vault) findCredentials(profile string) (home string, who Who, path string, data []byte, err error) {
	found := 0
	for _, h := range v.Homes() {
		w, werr := WhoOfHome(h)
		if werr != nil {
			continue
		}
		p := filepath.Join(h, ".aws", "credentials")
		b, _, rerr := w.Read(h, p)
		if rerr != nil {
			continue
		}
		lines, _ := splitLines(b)
		if _, vals, _ := awsProfile(lines, profile); vals["aws_access_key_id"] != "" && vals["aws_secret_access_key"] != "" {
			home, who, path, data = h, w, p, b
			found++
		}
	}
	switch found {
	case 0:
		err = ErrNoSuchSecret
	case 1:
	default:
		err = ErrAmbiguous
	}
	return
}

// StoreAWS moves the profile's keys into the vault and replaces them in the file with a
// credential_process entry. The original is not touched until the vault copy reads back
// identically.
func (v *Vault) StoreAWS(profile string) (*Entry, error) {
	if !profileRe.MatchString(profile) {
		return nil, errors.New("bad profile name")
	}
	home, who, path, orig, err := v.findCredentials(profile)
	if err != nil {
		return nil, err
	}
	id := idOf("aws", profile, who.Key())
	if _, err := v.Store.Get("m-" + id); err == nil {
		return nil, ErrExists
	}
	lines, eol := splitLines(orig)
	idx, vals, hasProc := awsProfile(lines, profile)
	if hasProc {
		return nil, errors.New("this profile already uses credential_process")
	}
	_, fi, err := who.Read(home, path)
	if err != nil {
		return nil, err
	}
	secret, _ := json.Marshal(map[string]any{
		"Version": 1, "AccessKeyId": vals["aws_access_key_id"], "SecretAccessKey": vals["aws_secret_access_key"],
		"SessionToken": vals["aws_session_token"],
	})
	// The rewritten file: key lines out, marker and credential_process in at the first key line.
	line := v.processLine(profile)
	var out []string
	for i, l := range lines {
		switch {
		case i == idx[0]:
			out = append(out, marker, line)
		case contains(idx, i):
		default:
			out = append(out, l)
		}
	}
	rewritten := []byte(strings.Join(out, eol))
	if bytes.Contains(rewritten, []byte(vals["aws_secret_access_key"])) {
		return nil, errors.New("the rewritten file would still hold the secret")
	}
	e := &Entry{ID: id, Kind: "aws", Ref: profile, Owner: who.Key(), UID: who.UID, GID: who.GID, Home: home, File: fi, Line: line, OrigSHA: sum(orig), RewrittenSHA: sum(rewritten), StoredAt: time.Now().UTC()}
	if err := v.put(id, e, orig, secret); err != nil {
		return nil, err
	}
	if err := who.Write(fi, rewritten); err != nil {
		v.drop(id)
		return nil, fmt.Errorf("rewriting the credentials file: %w", err)
	}
	if got, _, err := who.Read(home, path); err != nil || !bytes.Equal(got, rewritten) {
		_ = who.Write(fi, orig) // put it back before anything else
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

// Entry loads one manifest by owner.
func (v *Vault) Entry(owner, kind, ref string) (*Entry, error) {
	b, err := v.Store.Get("m-" + idOf(kind, ref, owner))
	if err != nil {
		return nil, err
	}
	var e Entry
	return &e, json.Unmarshal(b, &e)
}

// entriesFor lists the entries of a kind and reference, one per owner.
func (v *Vault) entriesFor(kind, ref string) ([]*Entry, error) {
	all, err := v.Entries()
	var out []*Entry
	for _, e := range all {
		if e.Kind == kind && e.Ref == ref {
			out = append(out, e)
		}
	}
	return out, err
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
func (v *Vault) AWSCredentialProcess(owner, profile string) ([]byte, error) {
	return v.Store.Get("s-" + idOf("aws", profile, owner))
}

// RestoreAWS puts the profile's keys back for every user who has it in the vault.
func (v *Vault) RestoreAWS(profile string) error {
	es, err := v.entriesFor("aws", profile)
	errs := []error{err}
	for _, e := range es {
		errs = append(errs, v.restoreAWS(e))
	}
	return errors.Join(errs...)
}

// restoreAWS: when the file is as Manar left it, the original bytes and permissions come back
// exactly; when the person edited it since, only Manar's lines are swapped for the original key
// lines.
func (v *Vault) restoreAWS(e *Entry) error {
	who := e.who()
	orig, err := v.Store.Get("o-" + e.ID)
	if err != nil {
		return fmt.Errorf("the vault has no original for this profile: %w", err)
	}
	cur, _, rerr := who.Read(e.Home, e.File.Path)
	switch {
	case rerr != nil && os.IsNotExist(rerr): // file removed meanwhile
		if err = who.MkdirAll(filepath.Dir(e.File.Path)); err == nil {
			err = who.Write(e.File, orig)
		}
	case rerr != nil:
		return rerr
	case sum(cur) == e.OrigSHA:
		err = nil
	case sum(cur) == e.RewrittenSHA:
		err = who.Write(e.File, orig)
	default:
		err = v.swapBack(who, e, cur, orig)
	}
	if err != nil {
		return err
	}
	// Verify before the vault forgets: the keys are in the file again.
	got, _, err := who.Read(e.Home, e.File.Path)
	if err != nil || !restored(got, orig, e.Ref) {
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

// swapBack replaces exactly the two lines Manar wrote for this entry (the marker and this
// entry's own credential_process line) with the original key lines.
func (v *Vault) swapBack(who Who, e *Entry, cur, orig []byte) error {
	ol, _ := splitLines(orig)
	oidx, _, _ := awsProfile(ol, e.Ref)
	var keyLines []string
	for _, i := range oidx {
		keyLines = append(keyLines, ol[i])
	}
	if e.Line == "" {
		return errors.New("the vault entry has no record of the line it wrote: edit the file by hand; the vault copy is kept")
	}
	cl, eol := splitLines(cur)
	var out []string
	done := false
	for i := 0; i < len(cl); i++ {
		if !done && cl[i] == marker && i+1 < len(cl) && cl[i+1] == e.Line {
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
	return who.Write(e.File, []byte(strings.Join(out, eol)))
}
