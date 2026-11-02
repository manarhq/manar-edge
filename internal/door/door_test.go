package door

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/manarhq/manar-edge/internal/hostclient"
	"github.com/manarhq/manar-edge/internal/pause"
)

type fakeAPI struct {
	mu      sync.Mutex
	batches []batch
	fail    bool
	err     error
}

func (f *fakeAPI) Do(_ context.Context, _, path string, in, _ any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
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
	d.loaded.Store(true)
	d.caller = func(*http.Request) (string, bool) { return "uid:1000", true }
	d.settings.Store(&hostclient.DoorSettings{Secrets: "mask"})
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
	if len(bt.Usage) != 1 || bt.Usage[0] != (usageItem{"host.codex-cli", "uid:1000", "openai", "gpt-5", 1, 11, 4}) {
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
	d.settings.Store(&hostclient.DoorSettings{Secrets: "block", Paused: []string{"gemini"}})
	res := post(t, front.URL, "/v1/chat/completions", "codex", `{"m":"password=Xk9#mQ2vLp8zR"}`)
	if res.StatusCode != 400 || len(*seen) != 0 {
		t.Fatalf("not blocked: %d %v", res.StatusCode, *seen)
	}
	// A pause is by provider: naming itself something else does not get a caller past it.
	res = post(t, front.URL, "/v1beta/models/x:generateContent", "codex_cli_rs/1", `{}`)
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

func TestStartsClosedUntilSettingsLoad(t *testing.T) {
	d, front, seen := newTestDoor(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{}`) })
	d.loaded.Store(false) // newTestDoor marks it loaded; undo for this test
	if res := post(t, front.URL, "/v1/chat/completions", "codex", `{"m":"hi"}`); res.StatusCode != 503 || len(*seen) != 0 {
		t.Fatalf("forwarded before settings: %d", res.StatusCode)
	}
	if !Healthy(front.URL) {
		t.Fatal("health must answer while waiting")
	}
	if got := New().settings.Load().Secrets; got != "block" {
		t.Fatalf("default secrets mode %q, want block", got)
	}
}

type fakeHost struct {
	fakeAPI
	cfg *hostclient.Config
	err error
}

func (f *fakeHost) Config(context.Context) (*hostclient.Config, error) { return f.cfg, f.err }

func TestCachedSettingsApplyOfflineAndFetchErrorsNeverRelax(t *testing.T) {
	dir := t.TempDir()
	d := New()
	d.stateDir = dir
	h := &fakeHost{cfg: &hostclient.Config{Door: &hostclient.DoorSettings{Secrets: "mask", Paused: []string{"host.codex-cli"}}}}
	d.refresh(context.Background(), h)
	if !d.loaded.Load() || d.settings.Load().Paused[0] != "host.codex-cli" {
		t.Fatal("first fetch not applied")
	}
	if fi, err := os.Stat(filepath.Join(dir, cacheFile)); err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("cache file: %v %v", fi, err)
	}
	// A restart with the API unreachable: the cache applies before serving.
	d2 := New()
	d2.stateDir = dir
	d2.loadCached()
	h.err, h.cfg = io.ErrUnexpectedEOF, nil
	d2.refresh(context.Background(), h)
	if !d2.loaded.Load() || d2.settings.Load().Secrets != "mask" || len(d2.settings.Load().Paused) != 1 {
		t.Fatalf("offline state wrong: %+v", d2.settings.Load())
	}
	// Garbage or a symlink as cache is ignored: stays closed.
	d3 := New()
	d3.stateDir = t.TempDir()
	_ = os.WriteFile(filepath.Join(d3.stateDir, cacheFile), []byte("{nope"), 0o600)
	d3.loadCached()
	if d3.loaded.Load() || d3.settings.Load().Secrets != "block" {
		t.Fatal("bad cache accepted")
	}
	d3.refresh(context.Background(), h)
	if d3.loaded.Load() {
		t.Fatal("a fetch error opened the gateway")
	}
}

func TestModelNamesAreCleanedAndRefusedBatchesDropped(t *testing.T) {
	if got := cleanModel("models/gemini 2.5;x"); got != "models/gemini_2.5_x" {
		t.Fatal(got)
	}
	r := newRecorder()
	r.usage("host.codex-cli", "openai", "uid:1", usage{Model: "gpt-5", In: 1})
	api := &fakeAPI{}
	api.err = &hostclient.StatusError{Code: 400, Message: "bad"}
	if r.flush(context.Background(), api) == nil || r.pending != nil {
		t.Fatal("a refused batch must be dropped, not resent forever")
	}
	r.usage("host.codex-cli", "openai", "uid:1", usage{Model: "gpt-5", In: 1})
	api.err = &hostclient.StatusError{Code: 429, Message: "slow down"}
	_ = r.flush(context.Background(), api)
	if r.pending == nil {
		t.Fatal("a rate-limited batch must be kept")
	}
}

func TestUnknownCallerRefusedAndMemoryBounds(t *testing.T) {
	d, front, seen := newTestDoor(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{}`) })
	d.caller = func(*http.Request) (string, bool) { return "", false }
	if res := post(t, front.URL, "/v1/chat/completions", "codex", `{}`); res.StatusCode != 403 || len(*seen) != 0 {
		t.Fatalf("unknown caller not refused: %d", res.StatusCode)
	}
	d.caller = func(*http.Request) (string, bool) { return "uid:1", true }
	// A body over the cap is refused, not cut.
	big := strings.NewReader(`{"a":"` + strings.Repeat("x", maxRequestBody) + `"}`)
	req, _ := http.NewRequest("POST", front.URL+"/v1/chat/completions", big)
	res, err := http.DefaultClient.Do(req)
	if err != nil || res.StatusCode != 413 || len(*seen) != 0 {
		t.Fatalf("oversized body: %v %v", res, err)
	}
}

func gz(t *testing.T, s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

func TestEncodingsAreReadOrRefusedInBothModes(t *testing.T) {
	for _, mode := range []string{"mask", "block"} {
		d, front, seen := newTestDoor(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{}`) })
		d.settings.Store(&hostclient.DoorSettings{Secrets: mode})
		send := func(enc string, body []byte) int {
			req, _ := http.NewRequest("POST", front.URL+"/v1/chat/completions", bytes.NewReader(body))
			req.Header.Set("Content-Encoding", enc)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			return res.StatusCode
		}
		for _, enc := range []string{"zstd", "br", "gzip, zstd", "deflate"} {
			if c := send(enc, []byte("x")); c != 415 {
				t.Errorf("%s/%s: %d, want 415", mode, enc, c)
			}
		}
		if len(*seen) != 0 {
			t.Fatalf("%s: an unreadable body reached the provider", mode)
		}
		// gzip, any case or spacing, is unpacked and scanned.
		if c := send(" GZip ", gz(t, `{"m":"AKIAIOSFODNN7EXAMPLE"}`)); (mode == "block" && c != 400) || (mode == "mask" && c != 200) {
			t.Errorf("%s: gzip with a key: %d", mode, c)
		}
		if mode == "mask" && strings.Contains((*seen)[0], "AKIA") {
			t.Fatal("gzip body not masked")
		}
		api := &fakeAPI{}
		_ = d.rec.flush(context.Background(), api)
		if api.batches[0].Refused != 4 {
			t.Fatalf("refused count %d", api.batches[0].Refused)
		}
	}
}

func TestSettingsWithoutDoorSectionKeepTheLastOnes(t *testing.T) {
	d := New()
	d.refresh(context.Background(), &fakeHost{cfg: &hostclient.Config{Door: &hostclient.DoorSettings{Secrets: "mask", Paused: []string{"openai"}}}})
	for _, cfg := range []*hostclient.Config{{}, {Door: &hostclient.DoorSettings{Unavailable: true}}} {
		d.refresh(context.Background(), &fakeHost{cfg: cfg})
		if s := d.settings.Load(); s.Secrets != "mask" || len(s.Paused) != 1 || !d.loaded.Load() {
			t.Fatalf("settings lost: %+v", s)
		}
	}
	e := New()
	e.refresh(context.Background(), &fakeHost{cfg: &hostclient.Config{}})
	if e.loaded.Load() {
		t.Fatal("an API with no door section opened a gateway that never had settings")
	}
}

func TestWorkspacePause(t *testing.T) {
	d, front, seen := newTestDoor(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{}`) })
	d.stateDir = t.TempDir()
	if err := pause.Set(d.stateDir, true); err != nil {
		t.Fatal(err)
	}
	if res := post(t, front.URL, "/v1/messages", "claude-cli/2", `{}`); res.StatusCode != 403 || len(*seen) != 0 {
		t.Fatalf("not paused: %d %v", res.StatusCode, *seen)
	}
	_ = pause.Set(d.stateDir, false)
	if res := post(t, front.URL, "/v1/messages", "claude-cli/2", `{}`); res.StatusCode != 200 {
		t.Fatalf("unpaused call refused: %d", res.StatusCode)
	}
}
