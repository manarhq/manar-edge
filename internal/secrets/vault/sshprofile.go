package vault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The shell snippet that points SSH_AUTH_SOCK at Manar's agent. It is a marked block added to the
// user's own profile files, never a rewrite: the original profile is kept in the vault (encrypted)
// and the block is cut out again by restore and by uninstall. The snippet only takes effect while
// the agent socket exists, and it remembers the previous agent in MANAR_UPSTREAM_SSH_AUTH_SOCK so
// Manar's agent can pass the user's other keys through.
const (
	blockBegin = "# >>> manar ssh agent (added by manar-edge; removed by `manar-edge vault restore --all` and uninstall) >>>"
	blockEnd   = "# <<< manar ssh agent <<<"
)

// AgentSocket is the per-user agent socket path. Tests change it.
var AgentSocket = func(uid int) string { return fmt.Sprintf("/run/manar-edge/ssh-%d.sock", uid) }

func snippet(sock string) string {
	return blockBegin + "\n" +
		fmt.Sprintf("if [ -S %q ]; then\n", sock) +
		"  export MANAR_UPSTREAM_SSH_AUTH_SOCK=\"${MANAR_UPSTREAM_SSH_AUTH_SOCK:-$SSH_AUTH_SOCK}\"\n" +
		fmt.Sprintf("  export SSH_AUTH_SOCK=%q\n", sock) +
		"fi\n" + blockEnd + "\n"
}

const fishSnippetName = ".config/fish/conf.d/manar-ssh.fish"

func fishSnippet(sock string) string {
	return fmt.Sprintf("# added by manar-edge; removed by `manar-edge vault restore --all` and uninstall\nif test -S %q\n  set -q MANAR_UPSTREAM_SSH_AUTH_SOCK; or set -gx MANAR_UPSTREAM_SSH_AUTH_SOCK $SSH_AUTH_SOCK\n  set -gx SSH_AUTH_SOCK %q\nend\n", sock, sock)
}

// profileFiles are the files that get the block when they exist (a login shell reads one of
// .bash_profile / .profile; .bashrc covers terminals; .zshenv covers zsh).
var profileFiles = []string{".profile", ".bash_profile", ".bashrc", ".zshenv"}

// profileBefore adds the block for this user (idempotent). The original of each file it changes is
// kept in the vault as pb-<owner>-<name> before the first change.
func (v *Vault) profileBefore(w Who, e *Entry) error {
	sock := AgentSocket(w.UID)
	changed := 0
	for _, rel := range profileFiles {
		p, ok := profilePath(e.Home, rel)
		if !ok {
			continue
		}
		b, fi, err := w.Read(e.Home, p)
		if err != nil {
			continue
		}
		if bytes.Contains(b, []byte(blockBegin)) {
			changed++
			continue
		}
		bk := "pb-" + sum([]byte(e.Owner + p))[:16]
		if _, err := v.Store.Get(bk); err != nil { // keep the first original only
			if err := v.Store.Put(bk, b); err != nil {
				return err
			}
		}
		nb := append(append([]byte{}, b...), []byte(nl(b)+snippet(sock))...)
		if err := w.Write(fi, nb); err != nil {
			return err
		}
		changed++
	}
	fish := filepath.Join(e.Home, fishSnippetName)
	if st, err := os.Stat(filepath.Dir(fish)); err == nil && st.IsDir() {
		if err := w.MkdirAll(filepath.Dir(fish)); err == nil {
			if err := w.Write(FileInfo{Path: fish, Mode: 0o644}, []byte(fishSnippet(sock))); err == nil {
				changed++
			}
		}
	}
	if changed == 0 { // no profile to extend: create ~/.profile, which every login shell can read
		p := filepath.Join(e.Home, ".profile")
		if _, err := os.Lstat(p); err == nil { // exists (a link we do not follow, or unreadable): leave it
			return errors.New("no shell profile Manar may change (a linked or unreadable ~/.profile)")
		}
		if err := w.Write(FileInfo{Path: p, Mode: 0o644}, []byte(snippet(sock))); err != nil {
			return err
		}
	}
	return nil
}

func nl(b []byte) string {
	if len(b) == 0 || b[len(b)-1] == '\n' {
		return ""
	}
	return "\n"
}

// profileAfterRestore removes the block once the user has no vaulted ssh key left.
func (v *Vault) profileAfterRestore(w Who, e *Entry) {
	if left, _ := v.Entries(); true {
		for _, o := range left {
			if o.Kind == "ssh" && o.Owner == e.Owner {
				return
			}
		}
	}
	removeBlocks(w, e.Home, func(p string) []byte {
		b, _ := v.Store.Get("pb-" + sum([]byte(e.Owner + p))[:16])
		return b
	}, AgentSocket(w.UID))
	for _, rel := range profileFiles {
		if p, ok := profilePath(e.Home, rel); ok {
			_ = v.Store.Delete("pb-" + sum([]byte(e.Owner + p))[:16])
		}
	}
}

// removeBlocks cuts the Manar block out of the user's profile files and deletes the fish file.
// orig returns the saved original of a file; when the file is exactly original + block, the
// original comes back byte for byte.
func removeBlocks(w Who, home string, orig func(path string) []byte, sock string) {
	for _, rel := range profileFiles {
		p, ok := profilePath(home, rel)
		if !ok {
			continue
		}
		b, fi, err := w.Read(home, p)
		if err != nil {
			continue
		}
		if o := orig(p); o != nil && bytes.Equal(b, append(append([]byte{}, o...), []byte(nl(o)+snippet(sock))...)) {
			_ = w.Write(fi, o)
			continue
		}
		i := bytes.Index(b, []byte(blockBegin))
		j := bytes.Index(b, []byte(blockEnd))
		if i < 0 || j < i {
			continue
		}
		end := j + len(blockEnd)
		if end < len(b) && b[end] == '\n' {
			end++
		}
		out := append(append([]byte{}, b[:i]...), b[end:]...)
		if len(bytes.TrimSpace(out)) == 0 && i == 0 {
			// the file only held our block (we created it): remove it
			_ = w.Remove(p)
			continue
		}
		_ = w.Write(fi, out)
	}
	fish := filepath.Join(home, fishSnippetName)
	if b, _, err := w.Read(home, fish); err == nil && strings.Contains(string(b), "added by manar-edge") {
		_ = w.Remove(fish)
	}
}

// profilePath resolves a profile file. A link (dotfile managers do this) is followed only when its
// target is inside the user's home; Who.Read then still checks the owner and refuses any link left
// in the resolved path.
func profilePath(home, rel string) (string, bool) {
	p := filepath.Join(home, rel)
	if _, err := os.Lstat(p); err != nil {
		return "", false
	}
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", false
	}
	h, err := filepath.EvalSymlinks(home)
	if err != nil || !strings.HasPrefix(r, h+string(filepath.Separator)) {
		return "", false
	}
	return r, true
}
