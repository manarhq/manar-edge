//go:build windows

package safefs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErrLink means a symbolic link, junction or mount point is in the path. Nothing was done.
var ErrLink = errors.New("a symbolic link, junction or mount point is in the path")

// Folder handles: enough to look inside and to name things relative to the folder. Shared for
// reading and writing, never for delete, so the folder cannot be renamed or replaced while held.
const (
	dirAccess = windows.FILE_LIST_DIRECTORY | windows.FILE_TRAVERSE | windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE
	dirShare  = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE
)

// openRel opens one name relative to the folder handle dir. The name must be a single path
// element. OBJ_DONT_REPARSE makes the kernel fail rather than follow any reparse point while it
// resolves the name; FILE_OPEN_REPARSE_POINT opens a link in that place as itself, and the caller
// then refuses it by its attributes.
func openRel(dir windows.Handle, name string, access, share, disposition, options uint32) (windows.Handle, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `\/:`) {
		return 0, fmt.Errorf("not a single file name: %q", name)
	}
	n, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	oa := windows.OBJECT_ATTRIBUTES{RootDirectory: dir, ObjectName: n, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE}
	oa.Length = uint32(unsafe.Sizeof(oa))
	var h windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&h, access, &oa, &iosb, nil, windows.FILE_ATTRIBUTE_NORMAL, share, disposition,
		options|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	switch {
	case err == nil:
		return h, nil
	case errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND), errors.Is(err, windows.STATUS_OBJECT_PATH_NOT_FOUND):
		return 0, os.ErrNotExist
	case errors.Is(err, windows.STATUS_REPARSE_POINT_ENCOUNTERED):
		return 0, ErrLink
	}
	return 0, err
}

// check refuses a handle that is a reparse point, of the wrong kind, or (for files) has more than
// one name: a hard link to a file elsewhere must not be read or written as if it were the user's.
func check(h windows.Handle, dir bool) error {
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		return err
	}
	if fi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrLink
	}
	if isDir := fi.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0; isDir != dir {
		if dir {
			return errors.New("not a folder")
		}
		return errors.New("not a regular file")
	}
	if !dir && fi.NumberOfLinks > 1 {
		return errors.New("the file has more than one name (a hard link)")
	}
	return nil
}

// split returns the path's elements below home. path must lie strictly below home.
func split(home, path string) ([]string, error) {
	home, path = filepath.Clean(home), filepath.Clean(path)
	if !filepath.IsAbs(home) || !filepath.IsAbs(path) {
		return nil, errors.New("path outside the user's home")
	}
	rel, err := filepath.Rel(home, path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, `..\`) {
		return nil, errors.New("path outside the user's home")
	}
	return strings.Split(rel, `\`), nil
}

// openHome opens a folder by walking from its drive's root, one element at a time. Every
// element must be a plain folder: the home itself and everything above it.
func openHome(home string) (windows.Handle, error) {
	home = filepath.Clean(home)
	vol := filepath.VolumeName(home)
	if len(vol) != 2 || vol[1] != ':' || !filepath.IsAbs(home) {
		return 0, errors.New("the home folder is not on a local drive")
	}
	root, err := windows.UTF16PtrFromString(`\\?\` + vol + `\`)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateFile(root, dirAccess, dirShare, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, err
	}
	rest := strings.Trim(home[len(vol):], `\`)
	if rest == "" {
		return h, nil
	}
	for _, name := range strings.Split(rest, `\`) {
		next, err := openDir(h, name, windows.FILE_OPEN)
		windows.CloseHandle(h)
		if err != nil {
			return 0, err
		}
		h = next
	}
	return h, nil
}

func openDir(parent windows.Handle, name string, disposition uint32) (windows.Handle, error) {
	h, err := openRel(parent, name, dirAccess, dirShare, disposition, windows.FILE_DIRECTORY_FILE)
	if err != nil {
		return 0, err
	}
	if err := check(h, true); err != nil {
		windows.CloseHandle(h)
		return 0, err
	}
	return h, nil
}

// openParent opens the folder that holds path, creating missing folders when create is set. It
// returns the folder handle and the file's own name.
func openParent(home, path string, create bool) (windows.Handle, string, error) {
	parts, err := split(home, path)
	if err != nil {
		return 0, "", err
	}
	h, err := openHome(home)
	if err != nil {
		return 0, "", err
	}
	disp := uint32(windows.FILE_OPEN)
	if create {
		disp = windows.FILE_OPEN_IF
	}
	for _, name := range parts[:len(parts)-1] {
		next, err := openDir(h, name, disp)
		windows.CloseHandle(h)
		if err != nil {
			return 0, "", err
		}
		h = next
	}
	return h, parts[len(parts)-1], nil
}

// Read returns the file's bytes (at most max); exists is false when it or a folder above it is
// not there.
func Read(home, path string, max int64) (data []byte, exists bool, err error) {
	dir, name, err := openParent(home, path, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer windows.CloseHandle(dir)
	h, err := openRel(dir, name, windows.GENERIC_READ|windows.SYNCHRONIZE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer windows.CloseHandle(h)
	if err := check(h, false); err != nil {
		return nil, false, err
	}
	buf := make([]byte, 64<<10)
	for {
		var n uint32
		rerr := windows.ReadFile(h, buf, &n, nil)
		data = append(data, buf[:n]...)
		if int64(len(data)) > max {
			return nil, true, errors.New("the file is too large")
		}
		if rerr != nil && !errors.Is(rerr, windows.ERROR_HANDLE_EOF) {
			return nil, true, rerr
		}
		if n == 0 || rerr != nil {
			return data, true, nil
		}
	}
}

// MkdirAll creates the folders down to dir, which must lie below home.
func MkdirAll(home, dir string) error {
	h, name, err := openParent(home, dir, true)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	d, err := openDir(h, name, windows.FILE_OPEN_IF)
	if err == nil {
		windows.CloseHandle(d)
	}
	return err
}

// Write replaces the file: a new temporary file in the same folder, then a rename over the
// target, both relative to the verified folder handle. Missing folders are created. A link or
// hard link already in the target's place is replaced, never written through.
func Write(home, path string, data []byte) error {
	dir, name, err := openParent(home, path, true)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(dir)
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	// FILE_CREATE fails if the name exists, and no sharing: nobody else can open it meanwhile.
	h, err := openRel(dir, ".manar-"+hex.EncodeToString(rnd[:]), windows.GENERIC_WRITE|windows.DELETE|windows.SYNCHRONIZE, 0,
		windows.FILE_CREATE, windows.FILE_NON_DIRECTORY_FILE)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	if err := writeAll(h, data); err != nil {
		_ = deleteHandle(h)
		return err
	}
	if err := renameHandle(h, name); err != nil {
		_ = deleteHandle(h)
		return err
	}
	return nil
}

func writeAll(h windows.Handle, data []byte) error {
	for len(data) > 0 {
		var n uint32
		if err := windows.WriteFile(h, data, &n, nil); err != nil {
			return err
		}
		data = data[n:]
	}
	return windows.FlushFileBuffers(h)
}

// fileRenameInformation is FILE_RENAME_INFORMATION (the flags word stands for ReplaceIfExists).
type fileRenameInformation struct {
	ReplaceIfExists uint32
	RootDirectory   windows.Handle
	FileNameLength  uint32
	FileName        [1]uint16
}

// renameHandle renames the open file to name inside the folder it is in. With no root directory
// and a bare name, the file system renames in place: no path is parsed, so nothing can redirect it.
func renameHandle(h windows.Handle, name string) error {
	u, err := windows.UTF16FromString(name)
	if err != nil {
		return err
	}
	u = u[:len(u)-1] // no terminator
	var info fileRenameInformation
	size := int(unsafe.Offsetof(info.FileName)) + len(u)*2
	buf := make([]byte, size)
	ri := (*fileRenameInformation)(unsafe.Pointer(&buf[0]))
	ri.ReplaceIfExists = 1
	ri.FileNameLength = uint32(len(u) * 2)
	copy(unsafe.Slice(&ri.FileName[0], len(u)), u)
	var iosb windows.IO_STATUS_BLOCK
	return windows.NtSetInformationFile(h, &iosb, &buf[0], uint32(size), windows.FileRenameInformation)
}

// deleteHandle marks the open file for deletion (FILE_DISPOSITION_INFORMATION.DeleteFile).
func deleteHandle(h windows.Handle) error {
	del := byte(1)
	var iosb windows.IO_STATUS_BLOCK
	return windows.NtSetInformationFile(h, &iosb, &del, 1, windows.FileDispositionInformation)
}

// Remove deletes the file. A missing file or folder is not an error. A link in the file's place
// is removed itself (opened with FILE_OPEN_REPARSE_POINT), never what it points to.
func Remove(home, path string) error {
	dir, name, err := openParent(home, path, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer windows.CloseHandle(dir)
	h, err := openRel(dir, name, windows.DELETE|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return deleteHandle(h)
}
