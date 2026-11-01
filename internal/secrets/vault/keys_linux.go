//go:build linux

package vault

import "context"

func platformKeys() *Keyring { return NewKeyring() }

type agentRunner interface {
	Ensure()
	Close()
}

func newAgentRunner(ctx context.Context, v *Vault, b *Broker) agentRunner {
	return &AgentServer{V: v, B: b, Ctx: ctx}
}
