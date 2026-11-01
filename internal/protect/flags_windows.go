package protect

import (
	"errors"
	"os"
	"syscall"
)

const oNoFollow = 0

// openRead opens with FILE_FLAG_OPEN_REPARSE_POINT, so a junction or link swapped in after
// checkPath is opened as itself, and refuses any file that carries the reparse attribute.
func openRead(path string) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil,
		syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) || errors.Is(err, syscall.ERROR_PATH_NOT_FOUND) {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	var fi syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(h, &fi); err != nil {
		syscall.CloseHandle(h)
		return nil, err
	}
	if fi.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		syscall.CloseHandle(h)
		return nil, errLink
	}
	return os.NewFile(uintptr(h), path), nil
}
