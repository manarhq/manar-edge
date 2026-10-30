package warden

import (
	"fmt"
	"strings"
)

// Lang is the prompt language: "en" or "ar".
type Lang string

const (
	EN Lang = "en"
	AR Lang = "ar"
)

// LangFromLocale picks the prompt language from a locale name such as "ar_AE.UTF-8" or "ar-AE".
func LangFromLocale(locale string) Lang {
	l := strings.ToLower(strings.TrimSpace(locale))
	if l == "ar" || strings.HasPrefix(l, "ar_") || strings.HasPrefix(l, "ar-") || strings.HasPrefix(l, "ar.") {
		return AR
	}
	return EN
}

// Text is a prompt ready to show.
type Text struct {
	Title    string // "WARDEN · Manar app on this device"
	Body     string
	Once     string
	Deny     string
	Console  string // shown instead of the buttons for a high-risk action
	RTL      bool
	ConsoleO bool
}

var toolNames = map[string]string{
	"host.claude-code":     "Claude Code",
	"host.claude-desktop":  "Claude Desktop",
	"host.cursor":          "Cursor",
	"host.windsurf":        "Windsurf",
	"host.vscode-copilot":  "VS Code Copilot",
	"host.copilot-cli":     "Copilot CLI",
	"host.codex-cli":       "Codex CLI",
	"host.chatgpt-desktop": "ChatGPT Desktop",
	"host.gemini-cli":      "Gemini CLI",
}

// ToolName is the name people know a tool by; an unknown id is shown as is, shortened.
func ToolName(toolID string) string {
	if n, ok := toolNames[toolID]; ok {
		return n
	}
	return clip(strings.TrimPrefix(toolID, "host."), 40)
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// Render builds the prompt text. The resource is clipped; Arabic puts the tool name and the
// resource in their own isolates so a path keeps its direction inside right-to-left text.
func Render(p Prompt, lang Lang) Text {
	res := clip(p.Resource, 120)
	name := ToolName(p.ToolID)
	t := Text{}
	if lang == AR {
		t = Text{
			Title: "WARDEN · تطبيق منار على هذا الجهاز",
			Once:  "موافقة مرة واحدة", Deny: "رفض",
			Console: "افتح وحدة التحكم لاتخاذ القرار", RTL: true,
		}
		t.Body = fmt.Sprintf("يريد ⁨%s⁩ %s ⁦%s⁩", name, arabicVerb(p), res)
	} else {
		t = Text{
			Title: "WARDEN · Manar app on this device",
			Once:  "Approve once", Deny: "Deny",
			Console: "Open the console to decide",
		}
		t.Body = fmt.Sprintf("%s wants to %s %s", name, englishVerb(p), res)
	}
	t.ConsoleO = p.ConsoleOnly
	return t
}

func englishVerb(p Prompt) string {
	switch {
	case p.ActionID == "secret.use":
		return "use the secret"
	case strings.HasPrefix(p.ActionID, "file.read"):
		return "read"
	case strings.HasPrefix(p.ActionID, "file.write"), strings.HasPrefix(p.ActionID, "file.delete"):
		return "change"
	case strings.HasPrefix(p.ActionID, "shell"), strings.HasPrefix(p.ActionID, "command"):
		return "run"
	}
	return "use"
}

func arabicVerb(p Prompt) string {
	switch {
	case p.ActionID == "secret.use":
		return "استخدام السر"
	case strings.HasPrefix(p.ActionID, "file.read"):
		return "قراءة"
	case strings.HasPrefix(p.ActionID, "file.write"), strings.HasPrefix(p.ActionID, "file.delete"):
		return "تعديل"
	case strings.HasPrefix(p.ActionID, "shell"), strings.HasPrefix(p.ActionID, "command"):
		return "تشغيل"
	}
	return "استخدام"
}
