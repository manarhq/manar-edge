//go:build windows

package watch

import "unsafe"

func unsafeSizeof[T any](e T) uintptr { return unsafe.Sizeof(e) }
