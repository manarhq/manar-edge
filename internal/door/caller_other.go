//go:build !linux && !windows

package door

import "net/http"

// callerOf cannot name the caller on this OS, so every request is refused (fail closed).
func callerOf(*http.Request) (string, bool) { return "", false }
