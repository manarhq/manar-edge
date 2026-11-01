package vault

// Agent is the ssh-agent the vault loads keys into.
type Agent interface {
	// Add loads the private key at path.
	Add(path string) error
	// Has reports whether the agent holds the key with this fingerprint (SHA256:...).
	Has(fingerprint string) (bool, error)
	// Remove drops the key at path from the agent.
	Remove(path string) error
	// Fingerprint reads the fingerprint of the key file and whether a passphrase protects it.
	Fingerprint(path string) (fp string, encrypted bool, err error)
}
