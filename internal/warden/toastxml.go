package warden

import (
	"bytes"
	"errors"
	"strings"

	toast "git.sr.ht/~jackmordaunt/go-toast/v2"
	"git.sr.ht/~jackmordaunt/go-toast/v2/tmpl"

	"github.com/manarhq/manar-edge/internal/lazyre"
)

var safeID = lazyre.New(`^[A-Za-z0-9_-]{1,64}$`)

// BuildToastXML renders the toast. The text is cleaned with Display again here, whatever the
// caller did, and the ids that go into button arguments must be plain. The XML is shown through the
// Windows Runtime only (see prompter_windows.go): the library's PowerShell fallback, which pastes
// the XML into a script, is never used, so a toast that cannot be shown is simply not shown.
func BuildToastXML(appID string, p Prompt, t Text) (string, error) {
	if !safeID.MatchString(p.ID) {
		return "", errors.New("warden: prompt id is not plain")
	}
	n := toast.Notification{
		AppID: appID, Title: Display(t.Title, 80), Body: Display2(t.Body, 700),
		ActivationType: toast.Foreground, Duration: toast.Long, Audio: toast.Silent,
	}
	if p.ConsoleOnly {
		n.Body += "\n" + Display(t.Console, 120)
	} else {
		for _, a := range []struct {
			label string
			d     Decision
		}{{t.Once, ApproveOnce}, {t.Deny, Deny}} {
			n.Actions = append(n.Actions, toast.Action{Type: toast.Foreground, Content: Display(a.label, 40), Arguments: ToastArgs(p.ID, a.d)})
		}
	}
	var out bytes.Buffer
	if err := tmpl.XMLTemplate.Execute(&out, n); err != nil {
		return "", err
	}
	return out.String(), nil
}

// Display2 is Display for text that already holds line breaks we added ourselves: each line is
// cleaned on its own and the breaks are kept.
func Display2(s string, max int) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = Display(l, max)
	}
	return clip(strings.Join(lines, "\n"), max)
}
