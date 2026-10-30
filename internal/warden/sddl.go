package warden

import (
	"errors"
	"regexp"
)

var sidPattern = regexp.MustCompile(`^S-1-\d+(-\d+)+$`)

// PipeSDDL is the Windows pipe's access list: protected (no inheritance), SYSTEM full access, and
// the one user's SID read and write. Nobody else, including other administrators, can open it.
// The SID is validated so it cannot add entries of its own. It lives outside the Windows file so
// the unit test runs everywhere.
func PipeSDDL(userSID string) (string, error) {
	if !sidPattern.MatchString(userSID) {
		return "", errors.New("warden: not a SID: " + userSID)
	}
	return "D:P(A;;GA;;;SY)(A;;GRGW;;;" + userSID + ")", nil
}
