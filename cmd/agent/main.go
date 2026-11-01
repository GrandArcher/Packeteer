// Command packeteer-agent is the probe-only agent (#230). It runs inside
// the operator's network, calls the controller over mutual TLS, and
// measures with a prober plugin. It has no BGP, no injection, and no UI.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/GrandArcher/Packeteer/internal/agent"
	_ "github.com/GrandArcher/Packeteer/internal/plugins/prober/icmp"
	_ "github.com/GrandArcher/Packeteer/internal/plugins/prober/tcp"
	_ "github.com/GrandArcher/Packeteer/internal/plugins/prober/udp"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("packeteer-agent", flag.ContinueOnError)
	fs.SetOutput(stderr)
	def := os.Getenv("PACKETEER_AGENT_CONFIG")
	if def == "" {
		def = "/etc/packeteer/agent.yaml"
	}
	path := fs.String("config", def, "agent config file (env PACKETEER_AGENT_CONFIG)")
	check := fs.Bool("check", false, "validate the config and exit")
	ver := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *ver {
		fmt.Fprintln(stderr, "packeteer-agent", version)
		return 0
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))
	cfg, err := agent.Load(*path)
	if err != nil {
		fmt.Fprintln(stderr, "config:", err)
		return 1
	}
	a, err := agent.New(cfg, nil, log)
	if err != nil {
		fmt.Fprintln(stderr, "config:", err)
		return 1
	}
	if *check {
		fmt.Fprintf(stderr, "ok: site %s, %d providers\n", cfg.Site, len(cfg.Providers))
		return 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("packeteer-agent starting", "version", version, "site", cfg.Site, "controller", cfg.ControllerURL)
	if err := a.Run(ctx); err != nil {
		fmt.Fprintln(stderr, "agent:", err)
		return 1
	}
	return 0
}
