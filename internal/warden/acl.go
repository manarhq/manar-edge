package warden

// Windows file protection for the helper binary. The pure decision lives here so it is tested on
// every platform; acl_windows.go reads the real owner and DACL and feeds it.

// Rights that let a principal change a file or the directory around it.
const (
	rightWriteData     = 0x00000002 // FILE_WRITE_DATA / FILE_ADD_FILE
	rightAppendData    = 0x00000004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
	rightDeleteChild   = 0x00000040 // FILE_DELETE_CHILD
	rightDelete        = 0x00010000
	rightWriteDAC      = 0x00040000
	rightWriteOwner    = 0x00080000
	rightGenericWrite  = 0x40000000
	rightGenericAll    = 0x10000000
	rightWriteAnything = rightWriteData | rightAppendData | rightDeleteChild | rightDelete | rightWriteDAC | rightWriteOwner | rightGenericWrite | rightGenericAll
)

// trustedSIDs may own and change files in Program Files: SYSTEM, Administrators, TrustedInstaller
// and CREATOR OWNER (a placeholder that resolves to the owner, checked separately).
var trustedSIDs = map[string]bool{
	"S-1-5-18":     true, // SYSTEM
	"S-1-5-32-544": true, // Administrators
	"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": true, // TrustedInstaller
	"S-1-3-0": true, // CREATOR OWNER
}

// OwnerTrusted reports whether sid may own the helper file or one of its directories.
func OwnerTrusted(sid string) bool { return trustedSIDs[sid] && sid != "S-1-3-0" }

// AllowACEWritable reports whether an ACCESS_ALLOWED entry gives an untrusted principal (a user,
// Users, Everyone, Authenticated Users) a right to change the object.
func AllowACEWritable(sid string, mask uint32) bool {
	return mask&rightWriteAnything != 0 && !trustedSIDs[sid]
}
