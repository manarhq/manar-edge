//go:build !linux && !windows

package warden

import "errors"

func NewPrompter() (Prompter, error) {
	return nil, errors.New("warden: this platform is not supported")
}
func SystemLang() Lang             { return EN }
func Install(string, string) error { return nil }
func Remove(string) error          { return nil }
