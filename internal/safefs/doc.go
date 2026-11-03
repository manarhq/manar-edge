// Package safefs reads, writes and removes files below a user's home folder on Windows, where the
// device service runs as SYSTEM and cannot become the user (Linux does that instead: see
// internal/protect/userfs_linux.go and internal/secrets/vault/who_linux.go).
//
// Checking a path and then using it is not safe there: between the two, the user can swap a
// folder for a junction (or a junction to \RPC Control with an object-manager link) and send a
// SYSTEM write or delete anywhere. So nothing here uses a path twice. Each folder is opened as a
// handle, one name at a time, relative to the handle of the folder above it, with
// OBJ_DONT_REPARSE (the kernel fails the open instead of following any link) and
// FILE_OPEN_REPARSE_POINT (a link in the last place is opened as itself, then refused). Files are
// then created, renamed and deleted relative to the verified folder handle, which is held open
// without FILE_SHARE_DELETE so the folder cannot be renamed or replaced meanwhile.
//
// Impersonating the user was the other choice. It needs the user's token, which the service only
// has while the user is signed in, and restore runs at uninstall or revocation when they may not
// be; the handle-relative approach works the same whether or not anyone is signed in.
package safefs
