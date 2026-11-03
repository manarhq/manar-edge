package protect

import "golang.org/x/sys/windows"

// longPath expands 8.3 short names in an existing path (GetLongPathName).
func longPath(p string) (string, error) {
	in, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return "", err
	}
	buf := make([]uint16, 1024)
	n, err := windows.GetLongPathName(in, &buf[0], uint32(len(buf)))
	if err != nil {
		return "", err
	}
	if n > uint32(len(buf)) {
		buf = make([]uint16, n)
		if n, err = windows.GetLongPathName(in, &buf[0], n); err != nil {
			return "", err
		}
	}
	return windows.UTF16ToString(buf[:n]), nil
}
