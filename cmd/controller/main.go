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
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	_ "github.com/GrandArcher/Packeteer/internal/plugins/all"
)

// DefaultConfigPath is where the container image expects the mounted config.
const DefaultConfigPath = "/etc/packeteer/config.yaml"

// ConfigEnv overrides the default config path when -config is not given.
const ConfigEnv = "PACKETEER_CONFIG"

// PluginDirEnv overrides the plugin directory from config.
const PluginDirEnv = "PACKETEER_PLUGIN_DIR"

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("controller", flag.ContinueOnError)
	fs.SetOutput(stderr)
	defaultPath := DefaultConfigPath
	if p := getenv(ConfigEnv); p != "" {
		defaultPath = p
	}
	path := fs.String("config", defaultPath, "path to the YAML config file (env "+ConfigEnv+")")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "packeteer %s\n", version)
		return 0
	}

	cfg, err := config.Load(*path)
	if err != nil {
		fmt.Fprintf(stderr, "packeteer: refusing to start: %v\n", err)
		return 1
	}

	plugins, err := pluginhost.Build(cfg, pluginhost.Options{Getenv: getenv, PluginDir: getenv(PluginDirEnv)})
	if err != nil {
		fmt.Fprintf(stderr, "packeteer: refusing to start: plugins: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "packeteer %s: config %s loaded\n", version, *path)
	fmt.Fprintf(stdout, "mode: %s\n", cfg.Mode)
	fmt.Fprintf(stdout, "max_improvements: %d\n", *cfg.MaxImprovements)
	fmt.Fprintf(stdout, "providers (%d):\n", len(cfg.Providers))
	for _, p := range cfg.Providers {
		fmt.Fprintf(stdout, "  - %s source_ip=%s next_hop=%s\n", p.Name, p.SourceIP, p.NextHop)
	}
	fmt.Fprintf(stdout, "plugins (%d):\n", len(plugins.Summary()))
	for _, line := range plugins.Summary() {
		fmt.Fprintf(stdout, "  - %s\n", line)
	}
	if cfg.Mode == config.ModeInject {
		fmt.Fprintln(stdout, "note: inject mode is not implemented yet; nothing will be announced")
	}
	fmt.Fprintln(stdout, "dry run: no probes sent, no BGP sessions opened")
	return 0
}
