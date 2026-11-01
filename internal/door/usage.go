package door

import (
	"bytes"
	"encoding/json"
	"io"
)

// usage is what a provider says it counted for one response.
type usage struct {
	Model     string
	In, Out   int64
	HasTokens bool
}

func num(m map[string]any, keys ...string) (int64, bool) {
	var total int64
	ok := false
	for _, k := range keys {
		if f, isNum := m[k].(float64); isNum && f >= 0 {
			total += int64(f)
			ok = true
		}
	}
	return total, ok
}

// merge folds a later reading in: token counts in streams are cumulative, so the largest wins.
func (u *usage) merge(o usage) {
	if o.Model != "" {
		u.Model = o.Model
	}
	if o.In > u.In {
		u.In = o.In
	}
	if o.Out > u.Out {
		u.Out = o.Out
	}
	u.HasTokens = u.HasTokens || o.HasTokens
}

// extract reads the model and token counts out of one decoded provider JSON object: Anthropic
// (usage.input_tokens, in message_start under "message"), OpenAI chat (prompt_tokens), OpenAI
// responses (usage under "response") and Gemini (usageMetadata).
func extract(v map[string]any, depth int) usage {
	var u usage
	for _, k := range []string{"model", "modelVersion"} {
		if s, ok := v[k].(string); ok && s != "" {
			u.Model = s
		}
	}
	if m, ok := v["usage"].(map[string]any); ok {
		// Anthropic cache reads and writes are separate counters; they are input tokens too.
		in, a := num(m, "input_tokens", "prompt_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")
		out, b := num(m, "output_tokens", "completion_tokens")
		u.In, u.Out, u.HasTokens = in, out, a || b
	}
	if m, ok := v["usageMetadata"].(map[string]any); ok {
		in, a := num(m, "promptTokenCount")
		out, b := num(m, "candidatesTokenCount", "thoughtsTokenCount")
		u.In, u.Out, u.HasTokens = in, out, a || b
	}
	if depth < 2 {
		for _, k := range []string{"message", "response"} {
			if m, ok := v[k].(map[string]any); ok {
				u.merge(extract(m, depth+1))
			}
		}
	}
	return u
}

const (
	maxJSONBuffer = 8 << 20 // a response bigger than this is passed on and not read for usage
	maxSSELine    = 1 << 20
)

// usageTee passes a response body through unchanged and reads the provider's token counts from
// it as it goes. Body text is only parsed in memory; it is never stored or logged.
type usageTee struct {
	rc     io.ReadCloser
	sse    bool
	buf    []byte // whole body (JSON) or the current partial line (SSE)
	over   bool
	got    usage
	done   func(usage)
	closed bool
}

func newUsageTee(rc io.ReadCloser, sse bool, done func(usage)) *usageTee {
	return &usageTee{rc: rc, sse: sse, done: done}
}

func (t *usageTee) Read(p []byte) (int, error) {
	n, err := t.rc.Read(p)
	if n > 0 {
		t.feed(p[:n])
	}
	if err != nil {
		t.finish()
	}
	return n, err
}

func (t *usageTee) Close() error {
	t.finish()
	return t.rc.Close()
}

func (t *usageTee) feed(b []byte) {
	if t.over {
		return
	}
	t.buf = append(t.buf, b...)
	if !t.sse {
		if len(t.buf) > maxJSONBuffer {
			t.over, t.buf = true, nil
		}
		return
	}
	for {
		i := bytes.IndexByte(t.buf, '\n')
		if i < 0 {
			break
		}
		t.line(t.buf[:i])
		t.buf = t.buf[i+1:]
	}
	if len(t.buf) > maxSSELine {
		t.buf = nil
	}
}

func (t *usageTee) line(l []byte) {
	l = bytes.TrimSpace(l)
	if !bytes.HasPrefix(l, []byte("data:")) {
		return
	}
	l = bytes.TrimSpace(l[5:])
	if !bytes.Contains(l, []byte("sage")) && !bytes.Contains(l, []byte("model")) { // usage, usageMetadata
		return
	}
	var v map[string]any
	if json.Unmarshal(l, &v) == nil {
		t.got.merge(extract(v, 0))
	}
}

func (t *usageTee) finish() {
	if t.closed {
		return
	}
	t.closed = true
	if t.sse && len(t.buf) > 0 && !t.over {
		t.line(t.buf)
	} else if !t.sse && !t.over {
		var v map[string]any
		if json.Unmarshal(t.buf, &v) == nil {
			t.got.merge(extract(v, 0))
		}
	}
	t.buf = nil
	t.done(t.got)
}
