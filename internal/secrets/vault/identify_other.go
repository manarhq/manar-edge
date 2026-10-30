//go:build !linux && !windows

package vault

import "errors"

func Identify(int) (Program, error) { return Program{}, errors.New("not supported on this OS") }
