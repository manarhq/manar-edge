package protect

import (
	"os"
	"syscall"
)

const oNoFollow = syscall.O_NOFOLLOW

// openRead never blocks on a FIFO or device (O_NONBLOCK) and never follows a link. The caller
// checks the opened file is a regular one before reading.
func openRead(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|oNoFollow|syscall.O_NONBLOCK, 0)
}
