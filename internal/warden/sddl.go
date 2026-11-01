package warden

import (
	"errors"
	"regexp"
)

var sidPattern = regexp.MustCompile(`^S-1-\d+(-\d+)+$`)

// pipeUserRights is FILE_GENERIC_READ | FILE_GENERIC_WRITE without FILE_APPEND_DATA (0x4), which on
// a pipe is FILE_CREATE_PIPE_INSTANCE: the user can connect, read and write, but cannot create a
// pipe instance with this name (no fake server next to the real one).
const pipeUserRights = "0x12019b"

// PipeSDDL is the Windows pipe's access list: protected (no inheritance), SYSTEM full access, and
// the one user's SID read and write without the right to create instances. Nobody else, including
// other administrators, can open it.
// The SID is validated so it cannot add entries of its own. It lives outside the Windows file so
// the unit test runs everywhere.
func PipeSDDL(userSID string) (string, error) {
	if !sidPattern.MatchString(userSID) {
		return "", errors.New("warden: not a SID: " + userSID)
	}
	return "D:P(A;;GA;;;SY)(A;;" + pipeUserRights + ";;;" + userSID + ")", nil
}
