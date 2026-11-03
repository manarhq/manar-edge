//go:build !linux

package protect

import "github.com/manarhq/manar-edge/internal/discovery"

// scanClaudeOverrides: only Linux lets the service read another process's arguments, environment
// and working folder cheaply. On Windows Manar sees the attempts its hooks refuse and its hook
// being taken out of a person's settings, not a project's own settings.
func scanClaudeOverrides([]discovery.Found) {}
