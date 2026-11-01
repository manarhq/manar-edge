package watch

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestClassOf(t *testing.T) {
	for p, want := range map[string]string{
		"/home/a/.aws/credentials":                                             ClassAWS,
		"/home/a/.aws/config":                                                  ClassAWS,
		"/home/a/.aws/cli/cache/x.json":                                        "",
		"/home/a/.ssh/id_ed25519":                                              ClassSSH,
		"/home/a/.ssh/id_ed25519.pub":                                          "",
		"/home/a/.ssh/known_hosts":                                             "",
		"/home/a/.ssh/config":                                                  "",
		`C:\Users\a\.ssh\deploy.pem`:                                           ClassSSH,
		"/home/a/.azure/accessTokens.json":                                     ClassAzure,
		"/home/a/.config/gcloud/legacy_credentials/x/adc.json":                 ClassGCloud,
		"/home/a/.kube/config":                                                 ClassKube,
		"/home/a/.kube/cache/discovery":                                        "",
		"/home/a/.docker/config.json":                                          ClassDocker,
		"/home/a/.config/google-chrome/Default/Cookies":                        ClassBrowser,
		"/home/a/.config/google-chrome/Default/Login Data":                     ClassBrowser,
		`C:\Users\a\AppData\Local\Microsoft\Edge\User Data\Default\Login Data`: ClassBrowser,
		"/home/a/.mozilla/firefox/x.default/logins.json":                       ClassBrowser,
		"/home/a/.mozilla/firefox/x.default/places.sqlite":                     "",
		"/home/a/code/app/.env":                                                ClassEnv,
		"/home/a/code/app/.env.production":                                     ClassEnv,
		"/home/a/code/app/.env.example":                                        "",
		"/home/a/code/app/environment.ts":                                      "",
	} {
		if got := ClassOf(p); got != want {
			t.Errorf("ClassOf(%q) = %q, want %q", p, got, want)
		}
	}
}

func TestDiscoverEnv(t *testing.T) {
	home := t.TempDir()
	mk := func(p string) {
		full := filepath.Join(home, p)
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		_ = os.WriteFile(full, []byte("X=1"), 0o600)
	}
	mk("code/a/.env")
	mk("code/a/.env.local")
	mk("code/a/.env.example")
	mk("code/a/node_modules/x/.env")
	mk("code/a/b/c/d/e/f/g/.env")
	mk("Downloads/.env")
	got := DiscoverEnv(home, 4, 100)
	for i := range got {
		got[i], _ = filepath.Rel(home, got[i])
	}
	sort.Strings(got)
	want := []string{"code/a/.env", "code/a/.env.local"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if n := len(DiscoverEnv(home, 4, 1)); n != 1 {
		t.Fatalf("max files not honoured: %d", n)
	}
}

func TestTargetsListed(t *testing.T) {
	home := t.TempDir()
	_ = os.MkdirAll(filepath.Join(home, ".config", "google-chrome", "Default", "Network"), 0o755)
	var classes []string
	for _, x := range Targets(home) {
		classes = append(classes, x.Class)
	}
	for _, c := range []string{ClassAWS, ClassSSH, ClassAzure, ClassGCloud, ClassKube, ClassDocker, ClassBrowser} {
		found := false
		for _, g := range classes {
			found = found || g == c
		}
		if !found {
			t.Errorf("missing class %s", c)
		}
	}
}
