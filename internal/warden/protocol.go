// Package warden is WARDEN, the desktop prompt of Manar ("Manar app on this device"). The device
// service runs where no one can see it (a Windows service lives in session 0), so a small
// per-user helper (`manar-edge warden`) shows the prompt and the service brokers to it over a
// local channel that only the allowed user can open: a named pipe with a DACL on Windows, a unix
// socket with an SO_PEERCRED check on Linux. Decisions go from the device to the API over the
// host mTLS channel (internal/hostclient), never from the helper.
package warden

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
)

// Decision is what a person chose.
type Decision string

const (
	ApproveOnce Decision = "approve_once"
	// ApproveEight exists only as the console's answer. A device never sends it: 8 hours is a
	// standing permission and is decided in a browser session.
	ApproveEight Decision = "approve_8h"
	Deny         Decision = "deny"
	// Dismissed is not a decision: the prompt was closed or timed out. The approval stays pending
	// (and expires), so a dismissed prompt never approves anything.
	Dismissed Decision = "dismissed"
)

// Valid reports whether d is something a person can choose.
func (d Decision) Valid() bool { return d == ApproveOnce || d == ApproveEight || d == Deny }

// Kind says what the prompt is about.
type Kind string

const (
	// KindAction is an AI tool asking to do something (from the API's pending approvals).
	KindAction Kind = "action"
)

// Prompt is what the service asks the helper to show.
type Prompt struct {
	ID       string `json:"id"`
	Kind     Kind   `json:"kind"`
	ToolID   string `json:"toolId,omitempty"`   // KindAction: host.cursor
	ActionID string `json:"actionId,omitempty"` // KindAction: file.read
	Resource string `json:"resource"`           // masked path, or the secret's name
	// ConsoleOnly: a high-risk action. The prompt says to open the console and has no approve button.
	ConsoleOnly bool `json:"consoleOnly,omitempty"`
	// ExplainEN and ExplainAR: what could go wrong, in plain words (from the API's templates).
	ExplainEN string `json:"explainEn,omitempty"`
	ExplainAR string `json:"explainAr,omitempty"`
}

// msg is one line on the wire, in either direction.
type msg struct {
	Type     string   `json:"type"` // prompt | answer | cancel
	Prompt   *Prompt  `json:"prompt,omitempty"`
	ID       string   `json:"id,omitempty"`
	Decision Decision `json:"decision,omitempty"`
}

const maxLine = 64 * 1024

type codec struct {
	r   *bufio.Reader
	enc *json.Encoder
}

func newCodec(rw io.ReadWriter) *codec {
	return &codec{r: bufio.NewReaderSize(rw, maxLine), enc: json.NewEncoder(rw)}
}

func (c *codec) send(m msg) error { return c.enc.Encode(m) }

func (c *codec) recv() (msg, error) {
	line, err := c.r.ReadBytes('\n')
	if err != nil {
		return msg{}, err
	}
	if len(line) > maxLine {
		return msg{}, errors.New("warden: line too long")
	}
	var m msg
	if err := json.Unmarshal(line, &m); err != nil {
		return msg{}, err
	}
	return m, nil
}
