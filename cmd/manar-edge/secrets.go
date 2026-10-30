package main

import (
	"gitlab.vax.sh/manar/manar-edge/internal/secrets/host"
	_ "gitlab.vax.sh/manar/manar-edge/internal/secrets/watch" // registers the secrets watcher with the device service
)

func init() { host.SetStateDir(defaultStateBase) }
