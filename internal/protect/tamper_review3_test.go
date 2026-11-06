package protect

import "testing"

// V6: renaming a wrapped MCP server to unwrap it is treated as "the person removed it": no report.
func TestRenamingAWrappedMCPServerToUnwrapItIsReported(t *testing.T) {
	r, p, recon := desktopRig(t)
	write(t, p, `{"mcpServers":{"a2":{"command":"node","args":["a.js"]}}}`)
	*r.events = nil
	recon()
	if !r.reported() {
		t.Errorf("FINDING: wrapped server 'a' renamed to 'a2' with its raw command: re-wrapped without a report")
	}
}
