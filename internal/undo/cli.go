package undo

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"time"
)

// Helper is `manar-edge __undo <op> [...]`: it runs as the user whose store it opens (the service
// starts it through RunAs) and prints one JSON line {"ok":bool,"error":"...","backup":"...","note":"..."}.
// The service names the store folder it recorded for the snapshot, so a different XDG_STATE_HOME
// in the helper cannot send it somewhere else.
func Helper(args []string, out io.Writer) int {
	reply := func(res *RestoreResult, err error) int {
		r := map[string]any{"ok": err == nil}
		if err != nil {
			r["error"] = err.Error()
		}
		if res != nil {
			r["backup"], r["note"] = res.Backup, res.Note
		}
		_ = json.NewEncoder(out).Encode(r)
		if err != nil {
			return 1
		}
		return 0
	}
	usage := errors.New("usage: __undo restore <id> <path> <store> <sha256> | prune <store> | purge <store>")
	if len(args) < 2 {
		return reply(nil, usage)
	}
	store := args[len(args)-1]
	if args[0] == "restore" {
		if len(args) != 5 {
			return reply(nil, usage)
		}
		store = args[3]
	}
	if !validStoreDir(store) {
		return reply(nil, errors.New("not a Manar snapshot folder"))
	}
	s, err := Open(store)
	if err != nil {
		return reply(nil, err)
	}
	switch args[0] {
	case "restore":
		res, err := s.Restore(args[1], args[2], args[4], time.Now())
		return reply(res, err)
	case "prune":
		s.Prune(time.Now())
		return reply(nil, nil)
	case "purge":
		return reply(nil, s.Purge())
	}
	return reply(nil, usage)
}

// validStoreDir accepts only a folder shaped like the one DefaultDir makes.
func validStoreDir(d string) bool {
	return filepath.IsAbs(d) && filepath.Clean(d) == d &&
		filepath.Base(d) == "undo" && filepath.Base(filepath.Dir(d)) == "manar-edge"
}

// Command is `manar-edge undo list|restore <id>`, for the person at the keyboard.
func Command(args []string, out io.Writer) error {
	usage := errors.New("usage: manar-edge undo list | undo restore <id>")
	if len(args) == 0 {
		return usage
	}
	s, err := OpenDefault()
	if err != nil {
		return err
	}
	switch args[0] {
	case "list":
		recs := s.List(time.Now())
		if len(recs) == 0 {
			fmt.Fprintln(out, "No saved copies. Manar saves a file before an AI tool changes it outside its project folder.")
		}
		for _, r := range recs {
			what := "changed"
			if !r.Exists {
				what = "created"
			}
			fmt.Fprintf(out, "%s  %s  %s  %s (%s)\n", r.ID, r.Taken.Local().Format("2006-01-02 15:04"), r.Tool, r.Path, what)
		}
		return nil
	case "restore":
		if len(args) != 2 {
			return usage
		}
		r, err := s.Load(args[1])
		if err != nil {
			return err
		}
		res, err := s.Restore(r.ID, r.Path, "", time.Now())
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Put %s back as it was.\n", r.Path)
		if res.Backup != "" {
			fmt.Fprintf(out, "The file as it was just before is saved too: manar-edge undo restore %s\n", res.Backup)
		}
		if res.Note != "" {
			fmt.Fprintln(out, res.Note)
		}
		return nil
	}
	return usage
}
