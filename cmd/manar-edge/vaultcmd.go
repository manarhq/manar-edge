package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/manarhq/manar-edge/internal/secrets/vault"
)

// cmdVault is `manar-edge vault add <path> | restore <key> | restore --all`. Nothing here needs the
// Manar API: the person's own key is moved and put back through the local service, and an
// administrator can put keys back directly from the vault folder even when the service is down.
func cmdVault(rest []string) error {
	usage := errors.New("usage: manar-edge vault add <path to a key in ~/.ssh> | vault restore <key name> | vault restore --all")
	switch {
	case len(rest) == 2 && rest[0] == "add":
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		p, err := filepath.Abs(rest[1])
		if err != nil {
			return err
		}
		if filepath.Dir(p) != filepath.Join(home, ".ssh") {
			return errors.New("only a key directly inside your own ~/.ssh folder can be moved")
		}
		ok, err := vault.SSHViaService("ssh-add", filepath.Base(p))
		if !ok {
			return errors.New("Manar's service is not running; start it (sudo systemctl start manar-edge) and try again")
		}
		if err != nil {
			return err
		}
		fmt.Printf("%s is in the Manar vault. Open a new terminal to use it; undo with: manar-edge vault restore %s\n", filepath.Base(p), filepath.Base(p))
		return nil
	case len(rest) == 2 && rest[0] == "restore":
		all, name := rest[1] == "--all", rest[1]
		if requireAdmin() == nil { // administrator: straight from the vault folder, no service needed
			var err error
			if all {
				err = restoreSecrets()
			} else {
				err = vault.New().RestoreSSH(name)
			}
			if err != nil {
				return err
			}
			fmt.Println("Done. The key file is back exactly as it was.")
			return nil
		}
		if all {
			name = ""
		}
		ok, err := vault.SSHViaService("ssh-restore", name)
		if !ok {
			return errors.New("Manar's service is not running: run this again with sudo (administrator), which works without the service")
		}
		if err != nil {
			return err
		}
		fmt.Println("Done. The key file is back exactly as it was.")
		return nil
	}
	return usage
}
