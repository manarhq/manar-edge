package ports

import "testing"

func TestDoorAndJailGatewayNeverShareAPort(t *testing.T) {
	if DoorPort == JailGatewayPort || DoorListen == JailGatewayListen {
		t.Fatal("DOOR and the JAIL gateway must use different ports")
	}
	if JailWindowsProxyPort == DoorPort || JailWindowsProxyPort == JailGatewayPort {
		t.Fatal("the Windows JAIL proxy must not share a port with DOOR or the JAIL gateway")
	}
	if DoorPort >= 1024 {
		t.Fatal("DOOR's port must be privileged so only root can take it")
	}
}
