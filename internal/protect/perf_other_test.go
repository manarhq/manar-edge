//go:build !linux

package protect

import "os"

func readFileForBench(p string) ([]byte, error) { return os.ReadFile(p) }
