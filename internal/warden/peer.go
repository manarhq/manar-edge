package warden

import "fmt"

// CheckUID is the policy behind the Linux socket check: root and the listed users only.
func CheckUID(uid uint32, allowed []uint32) error {
	if uid == 0 {
		return nil
	}
	for _, a := range allowed {
		if a == uid {
			return nil
		}
	}
	return fmt.Errorf("user %d is not allowed to use WARDEN on this device", uid)
}
