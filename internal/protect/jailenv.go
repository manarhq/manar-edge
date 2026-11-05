package protect

import (
	"strings"

	"github.com/manarhq/manar-edge/internal/ports"
)

// KindJSONEnv reverses JailEnvEdit on a settings file the user changed since.
const KindJSONEnv = "json-env"

// jailEnvKeys are the proxy variables JAIL sets in a tool's own settings `env` block.
var jailEnvKeys = []string{"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"}

// JailEnvEdit sets the given variables in the settings file's "env" object (Claude Code's
// settings.json: "Environment variables that will be applied to every session"). Other keys and
// other env variables are kept. A file that is not a plain JSON object is left alone.
func JailEnvEdit(path string, vars map[string]string) FileEdit {
	return FileEdit{Path: path, Kind: KindJSONEnv, Mode: 0o644, Edit: jsonObject(func(root map[string]any) error {
		env, err := objAt(root, "env")
		if err != nil {
			return err
		}
		for k, v := range vars {
			env[k] = v
		}
		return nil
	})}
}

// undoJSONEnv removes only values that are ours (a loopback proxy URL, or the NO_PROXY we set), so
// a proxy the user chose themselves after protection stays.
func undoJSONEnv(root map[string]any) error {
	env, ok := root["env"].(map[string]any)
	if !ok {
		return nil
	}
	for _, k := range jailEnvKeys {
		v, _ := env[k].(string)
		if strings.HasPrefix(v, "http://127.0.0.1:") || (k == "NO_PROXY" && v == JailNoProxy) {
			delete(env, k)
		}
	}
	if len(env) == 0 {
		delete(root, "env")
	}
	return nil
}

// JailNoProxy is the NO_PROXY value JAIL sets.
const JailNoProxy = ports.JailNoProxy

// SharedStore is the device's backup store (set up by Configure), for packages that edit tool
// settings next to protect.
func SharedStore() *Store { return theStore() }
