package undo

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
)

var editTools = map[string]bool{
	"edit": true, "multiedit": true, "write": true, "notebookedit": true, "write_file": true,
	"replace": true, "create": true, "str_replace": true, "str_replace_editor": true,
}

// EditTarget reads a tool's pre-tool hook input. It returns the file an edit tool is about to
// write (absolute, links resolved) and the tool's working folder. ok is false for anything that
// is not a file edit it understands; such calls are not snapshotted (shell commands and patch
// tools that name several files are not covered).
func EditTarget(raw []byte) (path, cwd string, ok bool) {
	var in struct {
		ToolName  string         `json:"tool_name"`
		ToolName2 string         `json:"toolName"`
		Cwd       string         `json:"cwd"`
		Input     map[string]any `json:"tool_input"`
		Args      map[string]any `json:"tool_args"`
	}
	if json.Unmarshal(raw, &in) != nil {
		return "", "", false
	}
	name := strings.ToLower(in.ToolName + in.ToolName2)
	if !editTools[name] {
		return "", "", false
	}
	args := in.Input
	if args == nil {
		args = in.Args
	}
	for _, k := range []string{"file_path", "absolute_path", "path", "filepath", "notebook_path"} {
		if s, _ := args[k].(string); s != "" {
			path = s
			break
		}
	}
	if path == "" {
		return "", "", false
	}
	if !filepath.IsAbs(path) {
		if in.Cwd == "" || !filepath.IsAbs(in.Cwd) {
			return "", "", false
		}
		path = filepath.Join(in.Cwd, path)
	}
	return resolve(filepath.Clean(path)), in.Cwd, true
}

// resolve follows links in the folder part (and in the file when it exists), so the answer to
// "is this inside the project" is about where the write will really land. A part that does not
// exist yet is kept as written.
func resolve(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	dir, base := filepath.Split(filepath.Clean(p))
	dir = filepath.Clean(dir)
	if dir == p {
		return p
	}
	return filepath.Join(resolve(dir), base)
}

// Outside says whether path is outside the project folder cwd. An unknown folder counts as
// outside, because snapshotting too much costs a few kilobytes and too little costs a file.
func Outside(path, cwd string) bool {
	if cwd == "" || !filepath.IsAbs(cwd) {
		return true
	}
	root := resolve(filepath.Clean(cwd))
	if runtime.GOOS == "windows" {
		path, root = strings.ToLower(path), strings.ToLower(root)
	}
	rel, err := filepath.Rel(root, path)
	return err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
