package protect

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os/exec"
	"sync"
	"time"
)

// Decider answers one MCP tool call. Relay.Decide is the real one.
type Decider func(ctx context.Context, actionID, resource string) Verdict

// RunMCPWrap is `manar-edge mcp-wrap <tool> <server> -- <command> [args]`: it stands between a
// tool and one stdio MCP server, passes every message through, and asks Manar before each
// `tools/call`. A denied call gets a JSON-RPC error and never reaches the server.
func RunMCPWrap(key, server string, argv []string, in io.Reader, out, errw io.Writer, decide Decider) int {
	if len(argv) == 0 {
		return 2
	}
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command (the MCP server command from the tool's own config, which this wrapper exists to run)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stderr = errw
	childIn, err := cmd.StdinPipe()
	if err != nil {
		return 1
	}
	childOut, err := cmd.StdoutPipe()
	if err != nil {
		return 1
	}
	if err := cmd.Start(); err != nil {
		io.WriteString(errw, "manar-edge: cannot start the MCP server: "+err.Error()+"\n")
		return 1
	}
	var mu sync.Mutex
	write := func(b []byte) {
		mu.Lock()
		defer mu.Unlock()
		out.Write(append(bytes.TrimRight(b, "\n"), '\n'))
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(childOut)
		sc.Buffer(make([]byte, 64<<10), 32<<20)
		for sc.Scan() {
			write(sc.Bytes())
		}
	}()
	// Messages are told apart cheaply. Only tools/call waits for a decision, and each waits in
	// its own goroutine, so pings, cancellations and other calls are never held up behind a
	// person deciding. Writes to the server are serialised.
	var inMu sync.Mutex
	send := func(b []byte) {
		inMu.Lock()
		defer inMu.Unlock()
		// nosemgrep: go.lang.security.audit.dangerous-command-write.dangerous-command-write (relays the MCP client's messages to the server it launched)
		childIn.Write(append(bytes.TrimRight(b, "\n"), '\n'))
	}
	var wg sync.WaitGroup
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), 32<<20)
	for sc.Scan() {
		line := append([]byte(nil), sc.Bytes()...)
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if !needsDecision(line) {
			if !validRPC(line) {
				write(parseError)
				continue
			}
			send(line)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			forward, replies := screen(line, server, decide)
			for _, r := range replies {
				write(r)
			}
			if forward != nil {
				send(forward)
			}
		}()
	}
	wg.Wait()
	childIn.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	if err := cmd.Wait(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		return 1
	}
	return 0
}

type rpcMsg struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params struct {
		Name string `json:"name"`
	} `json:"params"`
}

// screen returns what to forward to the server (nil for nothing) and the replies to send back.
// A batch is checked call by call so wrapping cannot be bypassed by sending an array.
func screen(line []byte, server string, decide Decider) (forward []byte, replies [][]byte) {
	t := bytes.TrimSpace(line)
	if len(t) == 0 {
		return nil, nil
	}
	if t[0] == '[' {
		var batch []json.RawMessage
		if json.Unmarshal(t, &batch) != nil {
			return nil, [][]byte{parseError}
		}
		var keep []json.RawMessage
		var errs []json.RawMessage
		for _, m := range batch {
			f, r := screen(m, server, decide)
			if f != nil {
				keep = append(keep, f)
			}
			for _, x := range r {
				errs = append(errs, x)
			}
		}
		if len(errs) > 0 {
			b, _ := json.Marshal(errs)
			replies = append(replies, b)
		}
		if len(keep) > 0 {
			forward, _ = json.Marshal(keep)
		}
		return forward, replies
	}
	var m rpcMsg
	if json.Unmarshal(t, &m) != nil {
		return nil, [][]byte{parseError}
	}
	if m.Method != "tools/call" {
		return line, nil
	}
	v := Verdict{false, "Manar: this MCP call has no tool name"}
	if m.Params.Name != "" {
		v = decide(context.Background(), "mcp", server+"/"+m.Params.Name)
	}
	if v.Allow {
		return line, nil
	}
	if len(m.ID) == 0 {
		return nil, nil // a notification cannot be answered
	}
	b, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": m.ID, "error": map[string]any{"code": -32000, "message": v.Reason},
	})
	return nil, [][]byte{b}
}

// parseError answers a line that is not JSON-RPC. It is never forwarded: a server might read it
// differently from how Manar did.
var parseError = []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Manar: this message is not valid JSON-RPC and was not passed on"}}`)

// needsDecision is true for a tools/call, or a batch holding one.
func needsDecision(line []byte) bool {
	t := bytes.TrimSpace(line)
	if len(t) == 0 {
		return false
	}
	if t[0] == '[' {
		var batch []json.RawMessage
		if json.Unmarshal(t, &batch) != nil {
			return true // screen answers it with a parse error
		}
		for _, m := range batch {
			if needsDecision(m) {
				return true
			}
		}
		return false
	}
	var m rpcMsg
	return json.Unmarshal(t, &m) == nil && m.Method == "tools/call"
}

// validRPC is true when line is a JSON object or array.
func validRPC(line []byte) bool {
	t := bytes.TrimSpace(line)
	var v any
	if json.Unmarshal(t, &v) != nil {
		return false
	}
	switch v.(type) {
	case map[string]any, []any:
		return true
	}
	return false
}
