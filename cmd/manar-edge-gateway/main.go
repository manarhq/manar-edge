// Command manar-edge-gateway is the WireGuard gateway agents reach Manar through.
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
	fmt.Fprintln(os.Stderr, "manar-edge-gateway: not implemented yet")
	os.Exit(1)
}
