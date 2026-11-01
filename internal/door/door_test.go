package door

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"gitlab.vax.sh/manar/manar-edge/internal/hostclient"
)

type fakeAPI struct {
	mu      sync.Mutex
	batches []batch
	fail    bool
}

func (f *fakeAPI) Do(_ context.Context, _, path string, in, _ any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail || path != "/ai-usage" {
		return io.ErrUnexpectedEOF
	}
	f.batches = append(f.batches, *in.(*batch))
	return nil
}

// newTestDoor points all three providers at one fake and returns what the fake saw.
func newTestDoor(t *testing.T, reply func(w http.ResponseWriter, r *http.Request)) (*Door, *httptest.Server, *[]string) {
	var seen []string
	var mu sync.Mutex
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, r.URL.Path+"|"+r.Header.Get("Authorization")+"|"+r.Header.Get("X-Manar-Evil")+"|"+string(b))
		mu.Unlock()
		reply(w, r)
	}))
	t.Cleanup(up.Close)
	u, _ := url.Parse(up.URL)
	d := New()
	d.anthropic.url, d.openai.url, d.gemini.url = u, u, u
	d.transport = http.DefaultTransport
	d.rp.Transport = http.DefaultTransport
	front := httptest.NewServer(d)
	t.Cleanup(front.Close)
	return d, front, &seen
}

func post(t *testing.T, base, path, ua, body string) *http.Response {
	req, _ := http.NewRequest("POST", base+path, strings.NewReader(body))
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Authorization", "Bearer user-own-key")
	req.Header.Set("X-Manar-Evil", "1")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestForwardsMasksAndCountsUsage(t *testing.T) {
	d, front, seen := newTestDoor(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"model":"gpt-5","usage":{"input_tokens":11,"output_tokens":4}}`)
	})
	res := post(t, front.URL, "/v1/responses", "codex_cli_rs/0.1", `{"input":"use AKIAIOSFODNN7EXAMPLE now"}`)
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(b), "gpt-5") {
		t.Fatalf("%d %s", res.StatusCode, b)
	}
	got := (*seen)[0]
	if !strings.HasPrefix(got, "/v1/responses|Bearer user-own-key||") || strings.Contains(got, "AKIA") || !strings.Contains(got, "[MANAR-MASKED:aws_access_key]") {
		t.Fatalf("upstream saw %q", got)
	}
	api := &fakeAPI{}
	if err := d.rec.flush(context.Background(), api); err != nil {
		t.Fatal(err)
	}
	bt := api.batches[0]
	if len(bt.Usage) != 1 || bt.Usage[0] != (usageItem{"host.codex-cli", "openai", "gpt-5", 1, 11, 4}) {
		t.Fatalf("usage %+v", bt.Usage)
	}
	if len(bt.Guard) != 1 || bt.Guard[0].Action != "masked" || bt.Guard[0].Sample != "AKIA****" {
		t.Fatalf("guard %+v", bt.Guard)
	}
	j, _ := json.Marshal(bt)
	if strings.Contains(string(j), "EXAMPLE") {
		t.Fatal("batch carries the secret")
	}
}

func TestBlockModeAndPause(t *testing.T) {
	d, front, seen := newTestDoor(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{}`) })
	d.settings.Store(&hostclient.DoorSettings{Secrets: "block", Paused: []string{"host.gemini-cli"}})
	res := post(t, front.URL, "/v1/chat/completions", "codex", `{"m":"password=hunter2hunter2"}`)
	if res.StatusCode != 400 || len(*seen) != 0 {
		t.Fatalf("not blocked: %d %v", res.StatusCode, *seen)
	}
	res = post(t, front.URL, "/v1beta/models/x:generateContent", "GeminiCLI/1", `{}`)
	if res.StatusCode != 429 || len(*seen) != 0 {
		t.Fatalf("not paused: %d", res.StatusCode)
	}
	res = post(t, front.URL, "/v1/chat/completions", "codex", `{"m":"hello"}`)
	if res.StatusCode != 200 {
		t.Fatalf("clean call refused: %d", res.StatusCode)
	}
	api := &fakeAPI{}
	_ = d.rec.flush(context.Background(), api)
	if g := api.batches[0].Guard; len(g) != 1 || g[0].Action != "blocked" {
		t.Fatalf("%+v", g)
	}
}

func TestStreamedUsageAndResend(t *testing.T) {
	d, front, _ := newTestDoor(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-4\",\"usage\":{\"input_tokens\":9,\"output_tokens\":1}}}\n\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":20}}\n\n")
	})
	res := post(t, front.URL, "/v1/messages", "claude-cli/2", `{"x":1}`)
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	api := &fakeAPI{fail: true}
	if d.rec.flush(context.Background(), api) == nil {
		t.Fatal("expected failure")
	}
	api.fail = false
	_ = d.rec.flush(context.Background(), api)
	_ = d.rec.flush(context.Background(), api) // nothing left
	if len(api.batches) != 1 || api.batches[0].Usage[0].OutputTokens != 20 || api.batches[0].Usage[0].Provider != "anthropic" {
		t.Fatalf("%+v", api.batches)
	}
}

func TestHealthChallengeRejectsImpostor(t *testing.T) {
	_, front, _ := newTestDoor(t, func(http.ResponseWriter, *http.Request) {})
	if !Healthy(front.URL) {
		t.Fatal("real door not healthy")
	}
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	defer fake.Close()
	if Healthy(fake.URL) {
		t.Fatal("a program that only answers 200 passed as DOOR")
	}
}

func TestUnknownRoute(t *testing.T) {
	_, front, _ := newTestDoor(t, func(http.ResponseWriter, *http.Request) {})
	if res := post(t, front.URL, "/admin", "x", `{}`); res.StatusCode != 404 {
		t.Fatal(res.StatusCode)
	}
}
