package vault

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"
)

type ipcRequest struct {
	Kind string `json:"kind"`
	Ref  string `json:"ref"`
}

type ipcReply struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data,omitempty"`
	Error string          `json:"error,omitempty"`
}

// handleConn serves one helper call. peerPID is the helper's own process id as the OS reports
// it; the requesting program is the helper's parent (the program that ran credential_process).
func handleConn(ctx context.Context, rw io.ReadWriter, peerPID int, b *Broker, parentExe func(pid int) string) {
	var req ipcRequest
	line, err := bufio.NewReaderSize(io.LimitReader(rw, 4096), 4096).ReadBytes('\n')
	reply := func(r ipcReply) { out, _ := json.Marshal(r); _, _ = rw.Write(append(out, '\n')) }
	if err != nil || json.Unmarshal(line, &req) != nil || !profileRe.MatchString(req.Ref) {
		reply(ipcReply{Error: "bad request"})
		return
	}
	data, err := b.Credential(ctx, Request{Kind: req.Kind, Ref: req.Ref, Program: parentExe(peerPID)})
	if err != nil {
		reply(ipcReply{Error: err.Error()})
		return
	}
	reply(ipcReply{OK: true, Data: data})
}

// Ask calls the daemon and returns the credential_process JSON. The wait covers the person
// deciding.
func askDaemon(rw io.ReadWriter, kind, ref string) ([]byte, error) {
	out, _ := json.Marshal(ipcRequest{Kind: kind, Ref: ref})
	if _, err := rw.Write(append(out, '\n')); err != nil {
		return nil, err
	}
	line, err := bufio.NewReader(io.LimitReader(rw, 1<<16)).ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var r ipcReply
	if err := json.Unmarshal(line, &r); err != nil {
		return nil, err
	}
	if !r.OK {
		return nil, errors.New(r.Error)
	}
	return r.Data, nil
}

// RunHelper is `manar-edge secret aws <profile>`: it prints the credential_process JSON.
func RunHelper(kind, ref string, w io.Writer) error {
	c, err := dialDaemon(5 * time.Second)
	if err != nil {
		return errors.New("Manar's service is not running; run `manar-edge secret restore` or ask for the keys back in the console")
	}
	defer c.Close()
	data, err := askDaemon(c, kind, ref)
	if err != nil {
		return err
	}
	_, err = w.Write(append(data, '\n'))
	return err
}
