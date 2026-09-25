// Command controller is the Packeteer entrypoint.
//
// M1: load and validate the config, then print the effective mode and
// providers. It does not open sockets, send probes, or speak BGP.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/GrandArcher/Packeteer/internal/config"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("controller", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "config.example.yaml", "path to the YAML config file")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := config.Load(*path)
	if err != nil {
		fmt.Fprintf(stderr, "packeteer: refusing to start: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "packeteer: config %s loaded\n", *path)
	fmt.Fprintf(stdout, "mode: %s\n", cfg.Mode)
	fmt.Fprintf(stdout, "max_improvements: %d\n", *cfg.MaxImprovements)
	fmt.Fprintf(stdout, "providers (%d):\n", len(cfg.Providers))
	for _, p := range cfg.Providers {
		fmt.Fprintf(stdout, "  - %s source_ip=%s next_hop=%s\n", p.Name, p.SourceIP, p.NextHop)
	}
	if cfg.Mode == config.ModeInject {
		fmt.Fprintln(stdout, "note: inject mode is not implemented yet; nothing will be announced")
	}
	fmt.Fprintln(stdout, "dry run: no probes sent, no BGP sessions opened")
	return 0
}
