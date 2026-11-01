//go:build !windows

package undo

import "syscall"

const oNoFollow = syscall.O_NOFOLLOW
