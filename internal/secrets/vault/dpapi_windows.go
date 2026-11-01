//go:build windows

package vault

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// DPAPI with the service account's key (the service is the only reader).
func protect(_ string, b []byte) ([]byte, error) { return crypt(b, true) }

func unprotect(_ string, b []byte) ([]byte, error) { return crypt(b, false) }

func crypt(b []byte, enc bool) ([]byte, error) {
	if len(b) == 0 {
		return b, nil
	}
	in := windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
	var out windows.DataBlob
	var err error
	if enc {
		err = windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	} else {
		err = windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}
