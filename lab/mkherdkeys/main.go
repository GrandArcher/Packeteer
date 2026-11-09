// Command mkherdkeys creates one herd node key per name for the herd lab
// (lab/e2e-herd.sh, #260) with the same loader the daemon uses, and prints
// "name public-key" lines. The keys are generated on every run in a
// temporary directory and never committed.
//
// Usage: mkherdkeys DIR NAME...
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/GrandArcher/Packeteer/internal/herd"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: mkherdkeys DIR NAME...")
		os.Exit(2)
	}
	for _, name := range os.Args[2:] {
		path := filepath.Join(os.Args[1], name+".key")
		n, err := herd.LoadNode(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "mkherdkeys:", err)
			os.Exit(1)
		}
		// The containers run as root, but a lab user may not.
		if err := os.Chmod(path, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "mkherdkeys:", err)
			os.Exit(1)
		}
		fmt.Println(name, n.PublicKey())
	}
}
