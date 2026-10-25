// Command manar-edge enrolls an agent, builds its network jail and runs it behind Manar.
package main

import (
	"fmt"
	"os"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println(version)
		return
	}
	fmt.Fprintln(os.Stderr, "usage: manar-edge <enroll|up|down|run|status|hook|install-claude-code|version>")
	os.Exit(2)
}
