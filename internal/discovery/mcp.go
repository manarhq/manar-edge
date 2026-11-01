package discovery

import (
	"encoding/json"
	"github.com/BurntSushi/toml"
	"gitlab.vax.sh/manar/manar-edge/internal/hostclient"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// MCPServer is one MCP server a protected tool is configured to start or call (see hostclient.MCPServer:
// no environment values, and no argument that looks like a secret, ever leave the device).
type MCPServer = hostclient.MCPServer

const (
	maskedValue = "***"
	maxServers  = 200
)

// mcpFile says where a tool keeps its MCP servers: a file relative to the account, and the key of
// the server map. Codex uses TOML ([mcp_servers.<name>] tables).
type mcpFile struct {
	Tool, Path, Key string
	TOML            bool
}

// MCPFiles are the MCP configs of the tools the catalogue knows (same files protect wraps).
// {home}, {config} and {local} expand like the catalogue's paths.
var MCPFiles = []mcpFile{
	{Tool: "host.claude-code", Path: "{home}/.claude.json", Key: "mcpServers"},
	{Tool: "host.claude-desktop", Path: "{config}/Claude/claude_desktop_config.json", Key: "mcpServers"},
	{Tool: "host.cursor", Path: "{home}/.cursor/mcp.json", Key: "mcpServers"},
	{Tool: "host.windsurf", Path: "{home}/.codeium/windsurf/mcp_config.json", Key: "mcpServers"},
	{Tool: "host.vscode-copilot", Path: "{config}/Code/User/mcp.json", Key: "servers"},
	{Tool: "host.gemini-cli", Path: "{home}/.gemini/settings.json", Key: "mcpServers"},
	{Tool: "host.codex-cli", Path: "{home}/.codex/config.toml", TOML: true},
	{Tool: "host.copilot-cli", Path: "{home}/.copilot/mcp-config.json", Key: "mcpServers"},
}

// UserReader reads one file of one account without ever following a link, as that account.
// internal/protect installs the real one (it runs a helper with the owner's uid on Linux).
type UserReader func(u User, path string) (data []byte, exists bool)

// MCPServers lists the servers configured for the found tools, for every account that uses them.
func MCPServers(found []Found, goos string, read UserReader) []MCPServer {
	var out []MCPServer
	seen := map[string]bool{}
	for _, f := range found {
		if f.Other {
			continue
		}
		for _, mf := range MCPFiles {
			if mf.Tool != f.ID {
				continue
			}
			for _, u := range f.Users {
				b, ok := read(u, expand(mf.Path, u, goos))
				if !ok {
					continue
				}
				var srvs []MCPServer
				if mf.TOML {
					srvs = parseCodexTOML(mf.Tool, b)
				} else {
					srvs = parseJSONServers(mf.Tool, mf.Key, b)
				}
				for _, s := range srvs {
					// Two accounts with the same server are one finding.
					k := s.Tool + "|" + s.Name + "|" + s.Command + "|" + strconv.Itoa(s.ArgCount) + "|" + s.Package + "@" + s.Version + "|" + s.URL
					if !seen[k] && len(out) < maxServers {
						seen[k] = true
						out = append(out, s)
					}
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Tool != out[j].Tool {
			return out[i].Tool < out[j].Tool
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func parseJSONServers(tool, key string, b []byte) []MCPServer {
	var root map[string]json.RawMessage
	if json.Unmarshal(b, &root) != nil {
		return nil
	}
	var out []MCPServer
	add := func(raw json.RawMessage) {
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) != nil {
			return
		}
		for name, r := range m {
			var s struct {
				Command   string            `json:"command"`
				Args      []any             `json:"args"`
				URL       string            `json:"url"`
				ServerURL string            `json:"serverUrl"`
				HTTPURL   string            `json:"httpUrl"`
				Type      string            `json:"type"`
				Env       map[string]any    `json:"env"`
				Headers   map[string]string `json:"headers"`
			}
			if json.Unmarshal(r, &s) != nil {
				continue
			}
			u := s.URL
			if u == "" {
				u = s.ServerURL
			}
			if u == "" {
				u = s.HTTPURL
			}
			out = append(out, build(tool, name, s.Command, anyStrings(s.Args), u, s.Type, safeEnvKeys(keysOf(s.Env, s.Headers))))
		}
	}
	if raw, ok := root[key]; ok {
		add(raw)
	}
	// Claude Code also keeps servers per project folder: projects.<path>.mcpServers.
	if tool == "host.claude-code" {
		var projects map[string]struct {
			M json.RawMessage `json:"mcpServers"`
		}
		if raw, ok := root["projects"]; ok && json.Unmarshal(raw, &projects) == nil {
			paths := make([]string, 0, len(projects))
			for p := range projects {
				paths = append(paths, p)
			}
			sort.Strings(paths)
			for _, p := range paths {
				if len(projects[p].M) > 0 {
					add(projects[p].M)
				}
			}
		}
	}
	return out
}

func anyStrings(in []any) []string {
	var out []string
	for _, v := range in {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func keysOf(ms ...any) []string {
	set := map[string]bool{}
	for _, m := range ms {
		switch v := m.(type) {
		case map[string]any:
			for k := range v {
				set[k] = true
			}
		case map[string]string:
			for k := range v {
				set[k] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

// safeEnvKeys keeps variable NAMES only, and only plain ones: a "name" that is really a pasted
// value (or has a secret's shape) is dropped.
func safeEnvKeys(keys []string) []string {
	out := []string{}
	for _, k := range keys {
		if envName.MatchString(k) && !looksSecret(k) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// parseCodexTOML reads [mcp_servers.<name>] from Codex's config.toml with a real TOML parser. Only
// command, args, url and the NAMES of env / env_vars are looked at; values are never kept. A file
// that does not parse reports nothing.
func parseCodexTOML(tool string, b []byte) []MCPServer {
	var doc struct {
		Servers map[string]struct {
			Command string         `toml:"command"`
			Args    []any          `toml:"args"`
			URL     string         `toml:"url"`
			Env     map[string]any `toml:"env"`
			EnvVars []any          `toml:"env_vars"`
		} `toml:"mcp_servers"`
	}
	if _, err := toml.Decode(string(b), &doc); err != nil {
		return nil
	}
	names := make([]string, 0, len(doc.Servers))
	for n := range doc.Servers {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []MCPServer
	for _, n := range names {
		r := doc.Servers[n]
		var env []string
		for k := range r.Env {
			env = append(env, k)
		}
		env = append(env, anyStrings(r.EnvVars)...)
		out = append(out, build(tool, n, r.Command, anyStrings(r.Args), r.URL, "", safeEnvKeys(env)))
	}
	return out
}

// unwrapMCP undoes `manar-edge mcp-wrap <tool> <server> -- <command> [args]`, so the inventory
// shows the server the user installed and not Manar's own wrapper.
func unwrapMCP(cmd string, args []string) (string, []string) {
	if strings.Contains(strings.ToLower(filepath.Base(cmd)), "manar-edge") && len(args) >= 4 && args[0] == "mcp-wrap" && args[3] == "--" && len(args) >= 5 {
		return args[4], args[5:]
	}
	return cmd, args
}

func build(tool, name, cmd string, args []string, rawURL, typ string, envKeys []string) MCPServer {
	cmd, args = unwrapMCP(cmd, args)
	s := MCPServer{Tool: tool, Name: clip(name, 100), EnvKeys: envKeys}
	if len(s.EnvKeys) > 40 {
		s.EnvKeys = s.EnvKeys[:40]
	}
	if rawURL != "" {
		s.URL = hostOnlyURL(rawURL)
		s.Transport = "http"
		if typ == "sse" || strings.HasSuffix(strings.TrimRight(strings.ToLower(rawURL), "/"), "/sse") {
			s.Transport = "sse"
		}
		return s
	}
	s.Transport = "stdio"
	s.Command = clip(commandBase(cmd), 100)
	s.ArgCount = len(args)
	s.Package, s.Version = packageOf(cmd, args)
	s.OutsideHome = outsideHome(args)
	return s
}

// commandBase is the program's file name without its folder or extension: folders can hold a
// user name, and nothing else in the command line is sent.
func commandBase(cmd string) string {
	b := filepath.Base(strings.ReplaceAll(cmd, `\`, "/"))
	for _, e := range []string{".exe", ".cmd", ".bat"} {
		b = strings.TrimSuffix(b, e)
	}
	if !safeName.MatchString(b) {
		return ""
	}
	return b
}

var (
	safeName    = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,100}$`)
	safePackage = regexp.MustCompile(`^(@[a-z0-9._-]+/)?[a-z0-9._-]+(/[a-z0-9._-]+)*$`)
	safeVersion = regexp.MustCompile(`^[A-Za-z0-9._+:^~<>=*-]{1,64}$`)
)

// hostOnlyURL keeps scheme, host and port. User names, passwords, paths, queries and fragments are
// all dropped: any of them can carry a key.
func hostOnlyURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	return clip(u.Scheme+"://"+u.Host, 200)
}

var systemRoots = map[string]bool{"etc": true, "var": true, "usr": true, "opt": true, "root": true, "srv": true, "mnt": true, "boot": true, "bin": true, "sbin": true, "lib": true, "sys": true, "proc": true, "windows": true, "programdata": true, "program files": true, "program files (x86)": true, "library": true, "system": true, "applications": true}

// outsideHome says an argument names the disk root, a system folder, or the folder that holds every
// account: a server given that can read and write well beyond the user's own files.
func outsideHome(args []string) bool {
	for _, a := range args {
		v := a
		if strings.HasPrefix(v, "-") {
			if _, rest, ok := strings.Cut(v, "="); ok {
				v = rest
			} else {
				continue
			}
		}
		v = strings.ReplaceAll(v, `\`, "/")
		if v == "/" || regexp.MustCompile(`^(?i)[a-z]:/?$`).MatchString(v) {
			return true
		}
		m := regexp.MustCompile(`^(?i)(?:[a-z]:)?/([^/]+)(/[^/]+)?`).FindStringSubmatch(v)
		if m == nil {
			continue
		}
		top := strings.ToLower(m[1])
		if systemRoots[top] || ((top == "home" || top == "users") && m[2] == "") {
			return true
		}
	}
	return false
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

var (
	secretValue = regexp.MustCompile(`^(sk-[A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{10,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{12,}|AIza[0-9A-Za-z_-]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*|npm_[A-Za-z0-9]{20,}|pypi-[A-Za-z0-9_-]{20,})`)
	tokenish    = regexp.MustCompile(`^[A-Za-z0-9_+=-]{20,}$`)
)

// looksSecret is a last check on the one thing taken from the arguments, the package spec: a token
// pasted where a package name should be is dropped, not sent.
func looksSecret(v string) bool {
	if secretValue.MatchString(v) {
		return true
	}
	if tokenish.MatchString(v) {
		var digit, letter bool
		for _, r := range v {
			digit = digit || (r >= '0' && r <= '9')
			letter = letter || (r|0x20 >= 'a' && r|0x20 <= 'z')
		}
		return digit && letter
	}
	return false
}

// launcher says which options a launcher is known to have: those that stand alone, and those that
// take a value. The value of an option is skipped and never reported. An option that is in neither
// list stops the search with no package: we cannot tell whether it swallows the next word.
type launcher struct {
	pre, free, val map[string]bool
	name           *regexp.Regexp
}

func set(ss ...string) map[string]bool {
	m := map[string]bool{}
	for _, s := range ss {
		m[s] = true
	}
	return m
}

var (
	npmName    = regexp.MustCompile(`^(@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*$`)
	pypiName   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)
	imageName  = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(:[0-9]{1,5})?(/[a-z0-9]+([._-][a-z0-9]+)*)*$`)
	npmLaunch  = launcher{pre: set("dlx", "exec", "x", "--"), free: set("-y", "--yes", "-q", "--quiet", "--no", "--prefer-offline", "--no-install", "--ignore-existing", "--bun", "-b"), val: set("-p", "--package", "--registry", "--cache", "--userconfig"), name: npmName}
	pyLaunch   = launcher{pre: set("run", "tool", "--"), free: set("--isolated", "--no-cache", "-q", "--quiet", "--refresh"), val: set("--from", "--with", "--python", "-p", "--spec", "--index-url", "--extra-index-url"), name: pypiName}
	dockLaunch = launcher{pre: set(), free: set("-i", "-t", "-it", "-ti", "--rm", "-d", "--init", "--read-only", "--interactive", "--tty"), val: set("-e", "--env", "-v", "--volume", "--name", "--network", "--net", "-p", "--publish", "--mount", "-w", "--workdir", "--user", "-u", "--env-file", "--platform", "--add-host", "--pull", "--memory", "-m", "--cpus"), name: imageName}
	launchers  = map[string]launcher{"npx": npmLaunch, "bunx": npmLaunch, "pnpm": npmLaunch, "yarn": npmLaunch, "bun": npmLaunch, "uvx": pyLaunch, "uv": pyLaunch, "pipx": pyLaunch, "docker": dockLaunch, "podman": dockLaunch}
)

// packageOf finds the package or image a launcher command starts and the version it pins:
// `npx -y @scope/pkg@1.2.3`, `uvx pkg==1.2.3`, `docker run -i image:tag`. A command that is not a
// known launcher, an option we do not know, or a name that is not shaped like a registry name
// gives no package.
func packageOf(cmd string, args []string) (pkg, version string) {
	base := strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(filepath.Base(strings.ReplaceAll(cmd, `\`, "/")), ".exe"), ".cmd"))
	l, ok := launchers[base]
	if !ok {
		return "", ""
	}
	rest := args
	if l.name == imageName {
		// docker run [options] IMAGE
		k := 0
		for k < len(rest) && rest[k] != "run" {
			if strings.HasPrefix(rest[k], "-") {
				return "", ""
			}
			k++
		}
		if k == len(rest) {
			return "", ""
		}
		rest = rest[k+1:]
	} else {
		n := 0
		for len(rest) > 0 && l.pre[rest[0]] {
			rest, n = rest[1:], n+1
		}
		// pnpm, yarn, bun, uv and pipx also have other commands (install, add...): only their
		// "run a package" forms are launchers.
		if n == 0 && map[string]bool{"pnpm": true, "yarn": true, "bun": true, "uv": true, "pipx": true}[base] {
			return "", ""
		}
	}
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		if !strings.HasPrefix(a, "-") {
			if strings.HasPrefix(a, ".") || strings.HasPrefix(a, "/") || strings.HasSuffix(a, ".js") || strings.HasSuffix(a, ".py") {
				return "", ""
			}
			if l.name == imageName {
				if i := strings.Index(a, "@sha256:"); i >= 0 {
					return splitImage(a[:i], a[i+1:])
				}
				if j := strings.LastIndex(a, ":"); j > strings.LastIndex(a, "/") {
					return splitImage(a[:j], a[j+1:])
				}
				return splitImage(a, "")
			}
			return splitSpec(a, l.name)
		}
		name, _, hasValue := strings.Cut(a, "=")
		switch {
		case l.free[a]:
		case l.val[name]:
			if !hasValue {
				i++
			}
		default:
			return "", ""
		}
	}
	return "", ""
}

func splitImage(name, ver string) (string, string) {
	if !imageName.MatchString(name) {
		return "", ""
	}
	return cleanPackage(name, ver)
}

// splitSpec splits `@scope/name@1.2.3`, `name@latest`, `name==1.2.0` or `name` into name and pin.
func splitSpec(s string, shape *regexp.Regexp) (string, string) {
	// A git or URL spec can carry credentials (git+https://user:token@host/repo): only scheme and
	// host are kept, as the "package".
	if strings.Contains(s, "://") {
		scheme, rest, _ := strings.Cut(s, "://")
		if !regexp.MustCompile(`^[a-z+]{3,12}$`).MatchString(strings.ToLower(scheme)) {
			return "", ""
		}
		host := rest
		if i := strings.LastIndex(host, "@"); i >= 0 && i < strings.IndexAny(host+"/", "/") {
			host = host[i+1:]
		}
		host = host[:strings.IndexAny(host+"/", "/?#")]
		if !regexp.MustCompile(`^[A-Za-z0-9.-]{1,100}(:[0-9]{1,5})?$`).MatchString(host) {
			return "", ""
		}
		return strings.ToLower(scheme) + "://" + host, ""
	}
	name, ver := s, ""
	if i := strings.Index(s, "=="); i > 0 {
		name, ver = s[:i], s[i+2:]
	} else if i := strings.LastIndex(s, "@"); i > 0 {
		name, ver = s[:i], s[i+1:]
	}
	if !strings.Contains(name, "://") && (shape == nil || !shape.MatchString(strings.ToLower(name)) && !shape.MatchString(name)) {
		return "", ""
	}
	return cleanPackage(name, ver)
}

// cleanPackage lets through only a plausible package name and version; anything else (a URL with
// credentials, a token, a path) is reported as no package.
func cleanPackage(name, ver string) (string, string) {
	if looksSecret(name) {
		return "", ""
	}
	name = strings.ToLower(name)
	if !safePackage.MatchString(name) || len(name) > 214 {
		return "", ""
	}
	if ver != "" && (!safeVersion.MatchString(ver) || looksSecret(ver)) {
		ver = ""
	}
	return name, ver
}
