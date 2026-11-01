package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"gitlab.vax.sh/manar/manar-edge/internal/discovery"
	"gitlab.vax.sh/manar/manar-edge/internal/protect"
)

// cmdHookTool is the hook installed in Cursor, Windsurf, Gemini CLI, Codex CLI and Copilot CLI.
// Any panic is a deny. A deny is exit 2 with the reason on stderr.
func cmdHookTool(args []string) (code int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(os.Stderr, "Manar: hook error")
			code = 2
		}
	}()
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "Manar: usage: manar-edge hook-tool <tool> <event>")
		return 2
	}
	out, errb, exit := protect.RunHook(args[0], args[1], os.Stdin)
	os.Stdout.Write(out)
	os.Stderr.Write(errb)
	return exit
}

// cmdMCPWrap is `mcp-wrap <tool> <server> -- <command> [args]`.
func cmdMCPWrap(args []string) int {
	if len(args) < 4 || args[2] != "--" {
		fmt.Fprintln(os.Stderr, "usage: manar-edge mcp-wrap <tool> <server> -- <command> [args...]")
		return 2
	}
	key, server, argv := args[0], args[1], args[3:]
	relay := protect.NewRelay()
	budget := time.Duration(protect.Budget(key)) * time.Second
	decide := func(ctx context.Context, action, resource string) protect.Verdict {
		return relay.Decide(ctx, key, action, resource, budget)
	}
	return protect.RunMCPWrap(key, server, argv, os.Stdin, os.Stdout, os.Stderr, decide)
}

// cmdProtect lists or undoes what Manar changed in other AI tools.
func cmdProtect(_ string, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: manar-edge protect list|restore [<tool>]")
	}
	if err := requireAdmin(); err != nil {
		return err
	}
	switch args[0] {
	case "list":
		printCoverage(out)
		return nil
	case "restore":
		if len(args) == 1 {
			return errors.Join(protect.RestoreEverything()...)
		}
		return protect.RestoreTool(args[1])
	}
	return errors.New("usage: manar-edge protect list|restore [<tool>]")
}

// printCoverage tells what Manar found and what it changed or will change. The service applies
// protection once the owner approves the device in the console.
func printCoverage(out io.Writer) {
	found := discovery.Scan(discovery.Users(), runtime.GOOS, discovery.OSProbe())
	if len(found) == 0 {
		fmt.Fprintln(out, "No AI tools found on this computer yet.")
		return
	}
	fmt.Fprintln(out, "AI tools found on this computer:")
	for _, f := range found {
		fmt.Fprintf(out, "  - %s\n", f.Name)
		for _, line := range protect.Changes(f) {
			fmt.Fprintf(out, "      %s\n", line)
		}
	}
	fmt.Fprintln(out, "Once you approve this computer in the console, Manar protects each tool it can: it adds a")
	fmt.Fprintln(out, "check before shell, file and MCP actions, and backs up every file first. Each change is listed")
	fmt.Fprintln(out, "on the AI tools page, where a switch per tool turns it off and puts the original back.")
	fmt.Fprintln(out, "Uninstalling restores every backup. See: manar-edge protect list")
}
