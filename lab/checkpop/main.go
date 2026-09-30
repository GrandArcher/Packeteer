// Command checkpop lists the paths a Packeteer instance has on an FRR
// edge, for the multi-POP lab (lab/e2e-multipop.sh, #30). It reads
// `show bgp ipv4 unicast json` on stdin and prints "prefix next_hop" for
// every path whose peer is the address given as the only argument,
// sorted and once each. It exits 2 when the input is not that JSON, so an
// empty list always means a real table.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: checkpop PEER < show-bgp.json")
		os.Exit(2)
	}
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	got, err := fromPeer(raw, os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "checkpop:", err)
		os.Exit(2)
	}
	for _, l := range got {
		fmt.Println(l)
	}
}

type path struct {
	PeerID   string    `json:"peerId"`
	Nexthops []nexthop `json:"nexthops"`
}

type nexthop struct {
	IP string `json:"ip"`
}

func fromPeer(raw []byte, peer string) ([]string, error) {
	text := string(raw)
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start < 0 || end < start {
		return nil, fmt.Errorf("no JSON object in input")
	}
	var table struct {
		Routes *map[string][]path `json:"routes"`
	}
	if err := json.Unmarshal([]byte(text[start:end+1]), &table); err != nil {
		return nil, err
	}
	if table.Routes == nil {
		return nil, fmt.Errorf("no routes object in input")
	}
	seen := map[string]bool{}
	var out []string
	for prefix, paths := range *table.Routes {
		for _, p := range paths {
			if p.PeerID != peer {
				continue
			}
			nh := "-"
			if len(p.Nexthops) > 0 {
				nh = p.Nexthops[0].IP
			}
			l := prefix + " " + nh
			if !seen[l] {
				seen[l] = true
				out = append(out, l)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}
