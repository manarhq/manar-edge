package jail

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"
)

type scripted struct {
	mu       sync.Mutex
	ask      string // JSON reply to /jail/ask
	statuses []string
	calls    []string
	lastBody map[string]any
	err      error
}

func (s *scripted) Do(_ context.Context, method, path string, in, out any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, method+" "+path)
	if s.err != nil {
		return s.err
	}
	switch {
	case path == "/jail/ask":
		return json.Unmarshal([]byte(s.ask), out)
	case method == http.MethodGet:
		r := s.statuses[0]
		if len(s.statuses) > 1 {
			s.statuses = s.statuses[1:]
		}
		return json.Unmarshal([]byte(r), out)
	}
	b, _ := json.Marshal(in) // the withdraw
	_ = json.Unmarshal(b, &s.lastBody)
	return nil
}

func TestAskerAnswers(t *testing.T) {
	cases := []struct {
		name     string
		ask      string
		statuses []string
		want     Result
	}{
		{"remembered allow", `{"decision":"allow"}`, nil, Result{Allow: true, Remember: -1, Reason: "rule"}},
		{"remembered deny", `{"decision":"deny"}`, nil, Result{Reason: "rule"}},
		{"once", `{"decision":"ask","id":"a1"}`, []string{`{"status":"PENDING"}`, `{"status":"APPROVED","decision":"approve_once"}`}, Result{Allow: true}},
		{"8 hours", `{"decision":"ask","id":"a1"}`, []string{`{"status":"APPROVED","decision":"approve_8h"}`}, Result{Allow: true, Remember: 8 * time.Hour}},
		{"always", `{"decision":"ask","id":"a1"}`, []string{`{"status":"APPROVED","decision":"approve_always"}`}, Result{Allow: true, Remember: -1}},
		{"denied", `{"decision":"ask","id":"a1"}`, []string{`{"status":"DENIED","decision":"deny"}`}, Result{Reason: "denied"}},
		{"expired", `{"decision":"ask","id":"a1"}`, []string{`{"status":"EXPIRED"}`}, Result{Reason: "denied_no_answer"}},
		{"revoked", `{"decision":"ask","id":"a1"}`, []string{`{"status":"PENDING"}`, `{"status":"REVOKED","decision":"approve_once"}`}, Result{Reason: "denied"}},
		{"approved without a known decision is not consent", `{"decision":"ask","id":"a1"}`, []string{`{"status":"APPROVED","decision":"surprise"}`}, Result{Reason: "denied"}},
	}
	for _, c := range cases {
		a := &APIAsker{API: &scripted{ask: c.ask, statuses: c.statuses}, Poll: time.Millisecond}
		got, err := a.Ask(context.Background(), claude, "x.example")
		if err != nil || got != c.want {
			t.Errorf("%s: %+v %v, want %+v", c.name, got, err, c.want)
		}
	}
}

func TestAskerErrorsAreNotConsent(t *testing.T) {
	for name, s := range map[string]*scripted{
		"api down":          {err: errors.New("offline")},
		"unknown decision":  {ask: `{"decision":"maybe"}`},
		"ask without an id": {ask: `{"decision":"ask"}`},
	} {
		a := &APIAsker{API: s, Poll: time.Millisecond}
		if r, err := a.Ask(context.Background(), claude, "x.example"); err == nil || r.Allow {
			t.Errorf("%s: %+v %v", name, r, err)
		}
	}
}

func TestAskerWithdrawsAfterTheWait(t *testing.T) {
	s := &scripted{ask: `{"decision":"ask","id":"a1"}`, statuses: []string{`{"status":"PENDING"}`}}
	a := &APIAsker{API: s, Poll: 5 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	r, err := a.Ask(ctx, claude, "x.example")
	if err == nil || r.Allow {
		t.Fatalf("%+v %v", r, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if last := s.calls[len(s.calls)-1]; last != "POST /approvals/a1/decide" {
		t.Fatalf("approval not withdrawn: %v", s.calls)
	}
	if w, _ := s.lastBody["withdraw"].(bool); !w || s.lastBody["decision"] != "deny" {
		t.Fatalf("the withdrawal must say it is one, not a person's deny: %v", s.lastBody)
	}
}
