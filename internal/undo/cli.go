package undo

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Helper is `manar-edge __undo <op> [...]`: it runs as the user whose store it opens (the service
// starts it through RunAs) and prints one JSON line {"ok":bool,"error":"..."}.
func Helper(args []string, out io.Writer) int {
	reply := func(err error) int {
		r := map[string]any{"ok": err == nil}
		if err != nil {
			r["error"] = err.Error()
		}
		_ = json.NewEncoder(out).Encode(r)
		if err != nil {
			return 1
		}
		return 0
	}
	if len(args) == 0 {
		return reply(errors.New("usage: __undo restore <id> <path> | prune | purge"))
	}
	s, err := OpenDefault()
	if err != nil {
		return reply(err)
	}
	switch args[0] {
	case "restore":
		if len(args) != 3 {
			return reply(errors.New("usage: __undo restore <id> <path>"))
		}
		return reply(s.Restore(args[1], args[2]))
	case "prune":
		s.Prune(time.Now())
		return reply(nil)
	case "purge":
		return reply(s.Purge())
	}
	return reply(errors.New("unknown operation"))
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
		if err := s.Restore(r.ID, r.Path); err != nil {
			return err
		}
		fmt.Fprintf(out, "Put %s back as it was.\n", r.Path)
		return nil
	}
	return usage
}
