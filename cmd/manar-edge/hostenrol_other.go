//go:build !windows

package main

import (
	"errors"
)

func cmdEnrolHost(base string, args []string) error {
	return errors.New("enrol (AD CS computer certificate) runs on domain-joined Windows only")
}
