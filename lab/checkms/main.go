// Command checkms lists the prefixes Packeteer has on an FRR edge, for
// the more-specific lab (lab/e2e-more-specific.sh, #56). It reads
// `show bgp ipv4 unicast json` on stdin and prints, sorted and once each,
// every prefix with a path from Packeteer: peer 192.0.2.10, or next hop
// 192.0.2.2 (transit-b) with local preference 250. It exits 2 when the
// input is not that JSON, so an empty list always means a real table.
//
// Constants match lab/packeteer-more-specific.yaml.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

const (
	peer      = "192.0.2.10"
	nextHop   = "192.0.2.2"
	localPref = 250
)

func main() {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	got, err := fromPacketeer(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "checkms:", err)
		os.Exit(2)
	}
	for _, p := range got {
		fmt.Println(p)
	}
}

type path struct {
	PeerID   string    `json:"peerId"`
	LocPrf   *int      `json:"locPrf"`
	Nexthops []nexthop `json:"nexthops"`
}

type nexthop struct {
	IP string `json:"ip"`
}

// fromPacketeer returns the prefixes in the table with a Packeteer path.
func fromPacketeer(raw []byte) ([]string, error) {
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
	var out []string
	for prefix, paths := range *table.Routes {
		for _, p := range paths {
			if fromUs(p) {
				out = append(out, prefix)
				break
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func fromUs(p path) bool {
	if p.PeerID == peer {
		return true
	}
	if p.LocPrf == nil || *p.LocPrf != localPref {
		return false
	}
	for _, nh := range p.Nexthops {
		if nh.IP == nextHop {
			return true
		}
	}
	return false
}
