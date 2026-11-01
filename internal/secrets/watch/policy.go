package watch

import (
	"slices"
	"strings"
)

// Mode is how far the Linux watcher goes. The founder default is ModeKeys.
type Mode int

const (
	// ModeAlert reports and never denies (no secrets.block feature).
	ModeAlert Mode = iota
	// ModeKeys denies an AI tool's own open of key and token files (ssh, cloud credentials,
	// npm, PyPI, GitHub) unless the person allowed that program; everything else is alert only.
	ModeKeys
	// ModeAll denies every watched class the same way ("block all").
	ModeAll
)

// Device features (GET /host/v1/config) that select the mode.
const (
	featureBlock    = "secrets.block"
	featureBlockAll = "secrets.block.all"
)

// ModeFromFeatures reads the mode from the device's feature list. "All" wins over "keys".
func ModeFromFeatures(features []string) Mode {
	switch {
	case slices.Contains(features, featureBlockAll):
		return ModeAll
	case slices.Contains(features, featureBlock):
		return ModeKeys
	}
	return ModeAlert
}

var keyClasses = map[string]bool{ClassSSH: true, ClassAWS: true, ClassAzure: true, ClassGCloud: true,
	ClassNPM: true, ClassPyPI: true, ClassGitHub: true}

// Blocks reports whether an AI tool's open of a file of this class may be denied in this mode.
func (m Mode) Blocks(class string) bool {
	switch m {
	case ModeAll:
		return class != ""
	case ModeKeys:
		return keyClasses[class]
	}
	return false
}

// Held reports whether opens of this class wait in the permission group even though they are
// not denied. .env files do: a notify-only event arrives after a short-lived process is gone and
// cannot be attributed, so an alert-only .env read would often be missed. Held opens are answered
// at once; they only gain attribution.
func (m Mode) Held(class string) bool { return m.Blocks(class) || (m == ModeKeys && class == ClassEnv) }

func (m Mode) String() string { return [...]string{"alert", "keys", "all"}[m] }

// ClassName is how a person says it.
func ClassName(class string) string {
	switch class {
	case ClassSSH:
		return "ssh keys"
	case ClassAWS:
		return "AWS credentials"
	case ClassAzure:
		return "Azure credentials"
	case ClassGCloud:
		return "Google Cloud credentials"
	case ClassNPM:
		return "npm tokens"
	case ClassPyPI:
		return "PyPI tokens"
	case ClassGitHub:
		return "GitHub tokens"
	}
	return strings.ToLower(class)
}
