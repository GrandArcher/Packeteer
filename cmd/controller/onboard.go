package main

import (
	"context"
	"fmt"
	"io"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/pbr"
	"github.com/GrandArcher/Packeteer/internal/snippet"
)

// hostIP runs the host's ip command. Tests replace it.
var hostIP pbr.Exec = pbr.HostExec

// runSnippet prints the router config for the configured edge (#221).
func runSnippet(vendor string, cfg *config.Config, stdout, stderr io.Writer) int {
	params, err := snippet.ForConfig(cfg)
	if err == nil {
		var text string
		if text, err = snippet.Join(vendor, params); err == nil {
			fmt.Fprint(stdout, text)
			return 0
		}
	}
	fmt.Fprintf(stderr, "packeteer: -snippet: %v\n", err)
	return 1
}

// runPBRApply shows what would change in the host's policy routing for the
// configured providers. When confirmed it makes the change and then asks the
// kernel which way each provider's probes leave (#221). It never touches a
// router.
func runPBRApply(ctx context.Context, cfg *config.Config, confirmed bool, run pbr.Exec, stdout, stderr io.Writer) int {
	entries := pbr.Entries(cfg)
	steps, err := pbr.Plan(ctx, run, entries)
	if err != nil {
		fmt.Fprintf(stderr, "packeteer: -pbr: %v\n", err)
		return 1
	}
	if len(steps) == 0 {
		fmt.Fprintln(stdout, "The host already has the policy routing for every provider.")
	}
	for _, s := range steps {
		fmt.Fprintln(stdout, s)
	}
	if len(steps) > 0 {
		if !confirmed {
			fmt.Fprintln(stdout, "Nothing was changed. Add -yes to apply these commands.")
			return 0
		}
		if err := pbr.Apply(ctx, run, steps); err != nil {
			fmt.Fprintf(stderr, "packeteer: -pbr: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Applied %d changes.\n", len(steps))
	}
	errs := pbr.Verify(ctx, run, entries)
	for _, e := range errs {
		fmt.Fprintf(stderr, "packeteer: -pbr: %v\n", e)
	}
	if len(errs) > 0 {
		return 1
	}
	fmt.Fprintln(stdout, "Every provider's probes leave through its next hop.")
	return 0
}
