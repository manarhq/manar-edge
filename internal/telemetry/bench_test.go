package telemetry

import "testing"

func BenchmarkRedactCommand(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Redact("git push https://user@github.com/a/b.git && curl -H 'Authorization: Bearer " + bearerVal + "' http://10.0.0.1/x?y=1")
	}
}

func BenchmarkRecordOff(b *testing.B) {
	enabled.Store(false)
	for i := 0; i < b.N; i++ {
		Record("jail", "t", "allow", "", "", 0)
	}
}
