package main

import (
	"context"
	"errors"
	"fmt"
	"net"

	"gitlab.vax.sh/manar/manar-edge/internal/warden"
)

// cmdWarden is `manar-edge warden`: the per-user helper that shows WARDEN prompts, started at
// logon (XDG autostart on Linux, HKCU Run on Windows). `warden windows-ui on|off` switches the
// Windows prompt, which is off until an administrator turns it on.
func cmdWarden(base string, args []string) error {
	if len(args) == 2 && args[0] == "windows-ui" {
		if err := requireAdmin(); err != nil {
			return err
		}
		switch args[1] {
		case "on", "off":
			s := warden.LoadSettings(base)
			s.WindowsUI = args[1] == "on"
			return warden.SaveSettings(base, s)
		}
	}
	if len(args) != 0 {
		return errors.New("usage: manar-edge warden [windows-ui on|off]")
	}
	pr, err := warden.NewPrompter()
	if err != nil {
		return fmt.Errorf("WARDEN cannot show prompts here: %w", err)
	}
	ctx, stop := signalContext()
	defer stop()
	return warden.RunHelper(ctx, func(c context.Context) (net.Conn, error) { return warden.Dial(c) }, pr, warden.SystemLang())
}
