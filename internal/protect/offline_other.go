//go:build !linux && !windows

package protect

import (
	"errors"
	"path/filepath"
)

func offlineDir(state string) string { return filepath.Clean(state) + "-policy" }

var readTrusted = func(string) ([]byte, error) { return nil, errors.New("not supported") }

func writeOffline(string, []byte) error { return errors.New("not supported") }

var localCaller = func() string { return "unknown" }
