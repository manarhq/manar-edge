package warden

import (
	"context"
	"strings"
	"testing"
	"time"
)

type fakeNotifier struct {
	ev      chan notifyEvent
	queued  []notifyEvent // delivered shortly after Notify, as a real click would be
	actions []string
	closed  []uint32
}

func (f *fakeNotifier) Notify(summary, body string, actions []string, urgent bool) (uint32, error) {
	f.actions = actions
	go func() {
		time.Sleep(30 * time.Millisecond)
		for _, e := range f.queued {
			f.ev <- e
		}
	}()
	return 7, nil
}
func (f *fakeNotifier) Close(id uint32) error      { f.closed = append(f.closed, id); return nil }
func (f *fakeNotifier) Events() <-chan notifyEvent { return f.ev }

func TestToastActionMapsToDecision(t *testing.T) {
	for key, want := range map[string]Decision{
		"approve_once": ApproveOnce, "approve_8h": Dismissed, "deny": Deny,
		"default": Dismissed, "": Dismissed, "approve_forever": Dismissed,
	} {
		if got := DecisionFromAction(key); got != want {
			t.Errorf("DecisionFromAction(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestPromptShowsThreeButtonsAndReturnsTheClick(t *testing.T) {
	f := &fakeNotifier{ev: make(chan notifyEvent, 4)}
	p := &notifyPrompter{n: f, timeout: time.Second}
	f.queued = []notifyEvent{{ID: 99, Action: actDeny}, {ID: 7, Action: actOnce}} // 99 is another notification
	pr := Prompt{ID: "a", Kind: KindAction, ToolID: "host.cursor", ActionID: "file.read", Resource: "~/.aws/credentials"}
	d, err := p.Show(context.Background(), pr, Render(pr, EN))
	if err != nil || d != ApproveOnce {
		t.Fatalf("Show = %q, %v", d, err)
	}
	if len(f.actions) != 4 || f.actions[1] != "Approve once" || f.actions[3] != "Deny" {
		t.Fatalf("actions = %v", f.actions)
	}
}

func TestClosingTheNotificationApprovesNothing(t *testing.T) {
	f := &fakeNotifier{ev: make(chan notifyEvent, 1)}
	p := &notifyPrompter{n: f, timeout: time.Second}
	f.queued = []notifyEvent{{ID: 7, Closed: true}}
	pr := Prompt{ID: "a"}
	if d, _ := p.Show(context.Background(), pr, Render(pr, EN)); d != Dismissed {
		t.Fatalf("closed notification gave %q", d)
	}
}

func TestHighRiskPromptHasNoApproveButtons(t *testing.T) {
	f := &fakeNotifier{ev: make(chan notifyEvent)}
	p := &notifyPrompter{n: f, timeout: time.Second}
	pr := Prompt{ID: "a", ConsoleOnly: true, ToolID: "host.cursor", ActionID: "shell.run", Resource: "rm -rf /"}
	d, _ := p.Show(context.Background(), pr, Render(pr, EN))
	if d != Dismissed || len(f.actions) != 0 {
		t.Fatalf("decision %q, actions %v", d, f.actions)
	}
}

func TestPromptTextEnglishAndArabic(t *testing.T) {
	pr := Prompt{Kind: KindAction, ToolID: "host.cursor", ActionID: "file.read", Resource: "~/.aws/credentials"}
	en := Render(pr, EN)
	if en.Title != "WARDEN · Manar app on this device" || en.Body != "Cursor wants to read ~/.aws/credentials" ||
		en.Once != "Approve once" || en.Deny != "Deny" || en.RTL {
		t.Fatalf("english: %+v", en)
	}
	ar := Render(pr, AR)
	if ar.Title != "WARDEN · تطبيق منار على هذا الجهاز" || ar.Once != "موافقة مرة واحدة" ||
		ar.Deny != "رفض" || !ar.RTL {
		t.Fatalf("arabic: %+v", ar)
	}
	if LangFromLocale("ar_AE.UTF-8") != AR || LangFromLocale("en_US") != EN || LangFromLocale("") != EN {
		t.Fatal("LangFromLocale")
	}
}

func TestWindowsToastArgsRoundTrip(t *testing.T) {
	for _, d := range []Decision{ApproveOnce, Deny} {
		id, got, ok := ParseToastArgs(ToastArgs("abc123", d))
		if !ok || id != "abc123" || got != d {
			t.Errorf("round trip %q: %q %q %v", d, id, got, ok)
		}
	}
	for _, bad := range []string{"", "close", "warden||deny", "warden|x|approve_forever", "warden|x|approve_8h", "other|x|deny", "warden|x|deny|y"} {
		if _, _, ok := ParseToastArgs(bad); ok {
			t.Errorf("ParseToastArgs(%q) accepted", bad)
		}
	}
}

func TestSitePromptsKeepTheEndOfALongName(t *testing.T) {
	long := "login.verify.account.update.paypal.com.secure-session.attacker-controlled-domain.example"
	tx := Render(Prompt{ToolID: "host.claude-code", ActionID: "site.connect", Resource: long}, EN)
	if !strings.HasSuffix(tx.Body, "attacker-controlled-domain.example") || !strings.Contains(tx.Body, "…") || strings.Contains(tx.Body, "login.verify") {
		t.Fatalf("%q", tx.Body)
	}
	short := Render(Prompt{ToolID: "host.claude-code", ActionID: "site.connect", Resource: "example.org"}, EN)
	if short.Body != "Claude Code wants to connect to example.org" {
		t.Fatalf("%q", short.Body)
	}
}
