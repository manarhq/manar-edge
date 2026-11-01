//go:build !linux

package vault

import "context"

// Windows keeps using the OpenSSH agent service (Agent); there is no Manar-run agent off Linux.
func platformKeys() *Keyring { return nil }

type agentRunner interface {
	Ensure()
	Close()
}

type noAgent struct{}

func (noAgent) Ensure() {}
func (noAgent) Close()  {}

func newAgentRunner(context.Context, *Vault, *Broker) agentRunner { return noAgent{} }
