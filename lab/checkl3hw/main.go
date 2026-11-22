// Command checkl3hw reads a RouterOS router's hardware routing state with
// the read-only L3HW reader (#736) and prints it as JSON. lab/e2e-chr.sh
// runs it against the disposable CHR, which has no switch chip, and expects
// "applicable": false. The login comes from PACKETEER_ROUTER_READ_USER and
// PACKETEER_ROUTER_READ_PASSWORD; it is never printed.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/routercheck/routeros"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func main() {
	if err := run(os.Args[1:], os.Getenv, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "checkl3hw:", err)
		os.Exit(1)
	}
}

func run(args []string, getenv func(string) string, stdout io.Writer) error {
	fs := flag.NewFlagSet("checkl3hw", flag.ContinueOnError)
	url := fs.String("url", "", "RouterOS REST base URL (https, or http to a loopback host)")
	wait := fs.Duration("timeout", time.Minute, "time limit for the whole read")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rd, err := routeros.Open(routeros.Config{
		URL: *url, UsernameEnv: "PACKETEER_ROUTER_READ_USER", PasswordEnv: "PACKETEER_ROUTER_READ_PASSWORD",
	}, plugin.Env{Getenv: getenv})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *wait)
	defer cancel()
	got, err := rd.ReadL3HW(ctx)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(got)
}
