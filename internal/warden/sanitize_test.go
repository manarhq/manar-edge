package warden

import (
	"strings"
	"testing"
)

// The payload an AI tool can put in a file path or command: it closes the toast's CDATA, adds markup,
// and carries PowerShell and shell substitutions plus bidi tricks.
const evil = "x]]><toast/>$(calc.exe)`whoami`‮⁦‏\x07\ny" + "]]]]>>"

func TestDisplayRemovesWhatCanBreakOutOfANotification(t *testing.T) {
	got := Display(evil, 120)
	for _, bad := range []string{"]]>", "$", "`", "<", ">", "‮", "⁦", "‏", "\x07", "\n"} {
		if strings.Contains(got, bad) {
			t.Errorf("%q still contains %q", got, bad)
		}
	}
	if long := Display(strings.Repeat("a", 500), 120); len([]rune(long)) > 120 {
		t.Errorf("not cut: %d", len([]rune(long)))
	}
	if Display("~/.aws/credentials", 120) != "~/.aws/credentials" {
		t.Error("a plain path must stay as it is")
	}
}

func TestRenderedPromptCarriesNoPayload(t *testing.T) {
	p := Prompt{ID: "ap1", ToolID: "host.cursor", ActionID: "shell", Resource: evil, ExplainEN: evil, ExplainAR: evil}
	for _, l := range []Lang{EN, AR} {
		b := Render(p, l).Body
		for _, bad := range []string{"]]>", "$(", "`", "<toast", "‮"} {
			if strings.Contains(b, bad) {
				t.Errorf("%s body contains %q: %q", l, bad, b)
			}
		}
	}
}

func TestToastXMLStaysInsideItsCDATA(t *testing.T) {
	p := Prompt{ID: "ap1", ToolID: "host.cursor", ActionID: "shell", Resource: evil, ExplainEN: evil}
	// Even a Text built by hand with the raw payload is cleaned when the XML is built.
	x, err := BuildToastXML("Manar.Warden", p, Text{Title: "WARDEN", Body: "Cursor wants to run " + evil, Once: "Approve once", Deny: "Deny"})
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(x, "<![CDATA["); n != strings.Count(x, "]]>") {
		t.Fatalf("CDATA opened %d times, closed %d times:\n%s", n, strings.Count(x, "]]>"), x)
	}
	for _, bad := range []string{"$(", "`whoami`", "<toast/>", "‮"} {
		if strings.Contains(x, bad) {
			t.Errorf("xml contains %q", bad)
		}
	}
	if _, err := BuildToastXML("Manar.Warden", Prompt{ID: `a"/><x`}, Text{}); err == nil {
		t.Error("a prompt id with markup must be refused")
	}
}
