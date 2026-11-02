package main

import (
	"fmt"

	"github.com/manarhq/manar-edge/internal/secrets/host"
	_ "github.com/manarhq/manar-edge/internal/secrets/vault" // registers the vault
	_ "github.com/manarhq/manar-edge/internal/secrets/watch" // registers the secrets watcher with the device service
)

func init() { host.SetStateDir(defaultStateBase) }

// cmdSecretRestoreAll is `manar-edge secret restore --all`: it puts every vaulted AWS key and ssh
// key back in its file. It asks the running service first, and checks the vault is empty.
func cmdSecretRestoreAll() error {
	if err := requireAdmin(); err != nil {
		return err
	}
	if err := restoreSecrets(); err != nil {
		return err
	}
	fmt.Println("Every vaulted secret is back in its file.")
	return nil
}
