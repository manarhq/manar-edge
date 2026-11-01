package jail

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"
)

// Asker turns "may this tool reach this site?" into a person's answer.
type Asker interface {
	Ask(ctx context.Context, tool, site string) (Result, error)
}

// doer is the part of hostclient.Client the asker needs (a fake in tests).
type doer interface {
	Do(ctx context.Context, method, path string, in, out any) error
}

// APIAsker asks through the API: it opens an approval (kind site.connect) that WARDEN shows on
// the desktop and the console and phone show too, and polls it. 8 hours and Always are decided
// only in the console or on the phone; the desktop prompt can say Allow once or Deny.
type APIAsker struct {
	API  doer
	Poll time.Duration
}

type askReply struct {
	Decision string `json:"decision"` // allow | deny | ask
	ID       string `json:"id"`
}

// Ask returns when the approval is decided or ctx ends (the 2-minute rule: then it is a refusal,
// the approval is withdrawn and the caller logs "denied: no answer").
func (a *APIAsker) Ask(ctx context.Context, tool, site string) (Result, error) {
	var r askReply
	if err := a.API.Do(ctx, http.MethodPost, "/jail/ask", map[string]string{"toolId": tool, "site": site}, &r); err != nil {
		return Result{}, err
	}
	switch r.Decision {
	case "allow":
		return Result{Allow: true, Remember: -1, Reason: "rule"}, nil
	case "deny":
		return Result{Reason: "rule"}, nil
	case "ask":
	default:
		return Result{}, errors.New("jail: unexpected answer from the API")
	}
	if r.ID == "" {
		return Result{}, errors.New("jail: the API did not open a prompt")
	}
	every := a.Poll
	if every == 0 {
		every = 2 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		var st struct {
			Status   string `json:"status"`
			Decision string `json:"decision"`
		}
		err := a.API.Do(ctx, http.MethodGet, "/approvals/"+url.PathEscape(r.ID), nil, &st)
		if err == nil {
			switch st.Status {
			case "APPROVED":
				switch st.Decision {
				case "approve_once":
					return Result{Allow: true}, nil
				case "approve_8h":
					return Result{Allow: true, Remember: 8 * time.Hour}, nil
				case "approve_always":
					return Result{Allow: true, Remember: -1}, nil
				}
				return Result{Reason: "denied"}, nil // an approval without a known decision is not consent
			case "DENIED":
				return Result{Reason: "denied"}, nil
			case "EXPIRED":
				return Result{Reason: "denied_no_answer"}, nil
			}
		}
		select {
		case <-ctx.Done():
			a.withdraw(r.ID)
			return Result{}, ctx.Err()
		case <-t.C:
		}
	}
}

// withdraw closes the prompt after the wait ran out so a late tap cannot allow a site nobody is
// waiting for any more. Best effort: the approval also expires on its own.
func (a *APIAsker) withdraw(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = a.API.Do(ctx, http.MethodPost, "/approvals/"+url.PathEscape(id)+"/decide", map[string]string{"decision": "deny"}, nil)
}
