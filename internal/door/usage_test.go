package door

import (
	"io"
	"strings"
	"testing"
)

func read(t *testing.T, body string, sse bool) usage {
	var got usage
	tee := newUsageTee(io.NopCloser(strings.NewReader(body)), sse, func(u usage) { got = u })
	if b, _ := io.ReadAll(tee); string(b) != body {
		t.Fatal("body changed")
	}
	tee.Close()
	return got
}

func TestUsageShapes(t *testing.T) {
	cases := []struct {
		name, body string
		sse        bool
		model      string
		in, out    int64
	}{
		{"anthropic json", `{"model":"claude-sonnet-4","usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":90}}`, false, "claude-sonnet-4", 100, 5},
		{"openai chat", `{"model":"gpt-4.1","usage":{"prompt_tokens":7,"completion_tokens":3}}`, false, "gpt-4.1", 7, 3},
		{"gemini", `{"modelVersion":"gemini-2.5-pro","usageMetadata":{"promptTokenCount":12,"candidatesTokenCount":4}}`, false, "gemini-2.5-pro", 12, 4},
		{"anthropic sse", "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-4\",\"usage\":{\"input_tokens\":25,\"output_tokens\":1}}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":42}}\n\n", true, "claude-opus-4", 25, 42},
		{"openai responses sse", "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"model\":\"gpt-5\",\"usage\":{\"input_tokens\":30,\"output_tokens\":8}}}\n\n", true, "gpt-5", 30, 8},
		{"gemini sse no trailing newline", "data: {\"usageMetadata\":{\"promptTokenCount\":3,\"candidatesTokenCount\":1},\"modelVersion\":\"gemini-2.5-flash\"}", true, "gemini-2.5-flash", 3, 1},
	}
	for _, c := range cases {
		u := read(t, c.body, c.sse)
		if u.Model != c.model || u.In != c.in || u.Out != c.out {
			t.Errorf("%s: got %+v", c.name, u)
		}
	}
}
