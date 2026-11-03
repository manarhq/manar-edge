package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
)

// FileInfo is what restore needs to put a file back exactly.
type FileInfo struct {
	Path string `json:"path"`
	Mode uint32 `json:"mode"`
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// Who is the person whose home a secret lives in. Every read and write below the home is done as
// that person (Linux: filesystem uid on the thread; Windows: handle-relative opens that refuse every
// reparse point, see internal/safefs), so the
// service, which runs as root or SYSTEM, can never be steered by a link in the user's folders
// into reading or writing something the user could not.
type Who struct {
	UID, GID int
	SID      string // Windows
	// Home is the home folder the files are below. Windows needs it to open every folder from the
	// drive's root down without following a link (internal/safefs).
	Home string
}

// Key identifies the owner inside vault ids and grants.
func (w Who) Key() string {
	if w.SID != "" {
		return w.SID
	}
	return "u" + itoa(w.UID)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	neg := n < 0
	if neg {
		n = -n
	}
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func (w Who) Exists(home, path string) bool {
	_, _, err := w.Read(home, path)
	return err == nil
}

// Same reports whether the file holds exactly want with the recorded mode.
func (w Who) Same(home string, fi FileInfo, want []byte) bool {
	got, cur, err := w.Read(home, fi.Path)
	return err == nil && bytes.Equal(got, want) && cur.Mode == fi.Mode
}
