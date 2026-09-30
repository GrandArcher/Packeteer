// Command mkgeoip writes a tiny MaxMind-format country database for the
// FRR labs: mkgeoip -o FILE PREFIX=CC ... Documentation prefixes only;
// real GeoIP data is never committed or downloaded.
package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/geoip/geoiptest"
)

func main() {
	out := flag.String("o", "", "output file")
	flag.Parse()
	if *out == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: mkgeoip -o FILE PREFIX=CC ...")
		os.Exit(2)
	}
	entries := map[string]string{}
	for _, a := range flag.Args() {
		p, cc, ok := strings.Cut(a, "=")
		if _, err := netip.ParsePrefix(p); !ok || err != nil || len(cc) != 2 {
			fmt.Fprintf(os.Stderr, "mkgeoip: %q is not PREFIX=CC\n", a)
			os.Exit(2)
		}
		entries[p] = cc
	}
	if err := os.WriteFile(*out, geoiptest.Build(entries), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "mkgeoip:", err)
		os.Exit(1)
	}
}
