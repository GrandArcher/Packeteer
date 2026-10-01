// Command interopcheck checks one prefix in an edge router's BGP table for
// the router interop matrix (lab/e2e-interop.sh, #53). It reads the
// router's own show output on stdin, turns it into one list of paths, and
// applies the same check whatever the router:
//
//	frr:   vtysh -c 'show bgp ipv4 unicast 198.51.100.0/24 json'
//	bird:  birdc show route all 198.51.100.0/24   (BIRD 2 and 3)
//	gobgp: gobgp global rib -a ipv4 198.51.100.0/24 -j
//
//	interopcheck -format bird -prefix 198.51.100.0/24 -want injected -nexthop 192.0.2.22
//
// A path is Packeteer's when it came from -peer (BIRD: or the protocol
// named -protocol) or carries -community. -want is one of:
//
//	injected  exactly one Packeteer path, it is the best path, from -peer,
//	          with -nexthop, -local-pref, -community, and no-export.
//	native    no Packeteer path, and a best path from another neighbor.
//	absent    no Packeteer path (other paths may exist, or none).
//
// Output the router could not have printed (empty, a failed CLI) is an
// error, never "absent". Exit status: 0 the check holds, 1 it does not
// (the reason goes to stderr), 2 bad usage or unreadable input.
// Documentation addresses and private ASNs only.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// noExport is the well-known NO_EXPORT community (RFC 1997).
const noExport = "65535:65281"

// Path is one router path for the prefix, whatever the router.
type Path struct {
	From        string   // neighbor address (BIRD: or protocol name when it prints none)
	Proto       string   // BIRD protocol name
	NextHop     string   // BGP next hop
	LocalPref   int      // -1 when the router did not print one
	Communities []string // "asn:value"; well-known ones numeric
	Best        bool
}

// Want is the check.
type Want struct {
	Mode      string // injected, native, absent
	Peer      string // Packeteer's address
	Protocol  string // BIRD protocol of the Packeteer session
	Community string // packeteer_community
	NextHop   string // injected only
	LocalPref int    // injected only
}

func main() {
	var w Want
	var format, prefix string
	fs := flag.NewFlagSet("interopcheck", flag.ContinueOnError)
	fs.StringVar(&format, "format", "", "router output: frr, bird, or gobgp")
	fs.StringVar(&prefix, "prefix", "", "prefix to check")
	fs.StringVar(&w.Mode, "want", "", "injected, native, or absent")
	fs.StringVar(&w.Peer, "peer", "192.0.2.10", "Packeteer's address")
	fs.StringVar(&w.Protocol, "protocol", "packeteer", "BIRD protocol name of the Packeteer session")
	fs.StringVar(&w.Community, "community", "64512:666", "packeteer_community")
	fs.StringVar(&w.NextHop, "nexthop", "", "next hop of the injected route")
	fs.IntVar(&w.LocalPref, "local-pref", 250, "local preference of the injected route")
	if err := fs.Parse(os.Args[1:]); err != nil || format == "" || prefix == "" ||
		!slices.Contains([]string{"injected", "native", "absent"}, w.Mode) || (w.Mode == "injected" && w.NextHop == "") {
		fmt.Fprintln(os.Stderr, "usage: interopcheck -format frr|bird|gobgp -prefix P -want injected -nexthop IP | -want native | -want absent")
		os.Exit(2)
	}
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	paths, err := Parse(format, prefix, string(raw))
	if err != nil {
		fmt.Fprintln(os.Stderr, "interopcheck:", err)
		os.Exit(2)
	}
	if err := Check(paths, w); err != nil {
		fmt.Fprintln(os.Stderr, "interopcheck:", err)
		os.Exit(1)
	}
}

// Parse reads one router's output for prefix.
func Parse(format, prefix, raw string) ([]Path, error) {
	switch format {
	case "frr":
		return parseFRR(prefix, raw)
	case "bird":
		return parseBIRD(prefix, raw)
	case "gobgp":
		return parseGoBGP(prefix, raw)
	}
	return nil, fmt.Errorf("unknown format %q", format)
}

// Check reports why paths do not match w, or nil.
func Check(paths []Path, w Want) error {
	var mine []Path
	for _, p := range paths {
		if w.isPacketeer(p) {
			mine = append(mine, p)
		}
	}
	switch w.Mode {
	case "absent":
		if len(mine) > 0 {
			return fmt.Errorf("%d Packeteer path(s), want none: %+v", len(mine), mine)
		}
		return nil
	case "native":
		if len(mine) > 0 {
			return fmt.Errorf("%d Packeteer path(s), want none: %+v", len(mine), mine)
		}
		for _, p := range paths {
			if p.Best {
				return nil
			}
		}
		return fmt.Errorf("no best path (have %d paths)", len(paths))
	}
	if len(mine) != 1 {
		return fmt.Errorf("%d Packeteer paths, want exactly 1: %+v", len(mine), mine)
	}
	p := mine[0]
	switch {
	case !p.Best:
		return fmt.Errorf("Packeteer's path is not the best path: %+v", p)
	case p.From != w.Peer:
		return fmt.Errorf("Packeteer's path is from %q, want %s", p.From, w.Peer)
	case p.NextHop != w.NextHop:
		return fmt.Errorf("next hop %q, want %s", p.NextHop, w.NextHop)
	case p.LocalPref != w.LocalPref:
		return fmt.Errorf("local preference %d, want %d", p.LocalPref, w.LocalPref)
	case !slices.Contains(p.Communities, w.Community):
		return fmt.Errorf("community %s missing (have %v)", w.Community, p.Communities)
	case !slices.Contains(p.Communities, noExport):
		return fmt.Errorf("no-export missing (have %v)", p.Communities)
	}
	return nil
}

func (w Want) isPacketeer(p Path) bool {
	return p.From == w.Peer || (p.Proto != "" && p.Proto == w.Protocol) || slices.Contains(p.Communities, w.Community)
}

// wellKnown maps community names routers print to numbers.
var wellKnown = map[string]string{
	"no-export":    noExport,
	"noexport":     noExport,
	"no-advertise": "65535:65282",
	"noadvertise":  "65535:65282",
	"blackhole":    "65535:666",
}

func community(c string) string {
	if n, ok := wellKnown[strings.ToLower(c)]; ok {
		return n
	}
	return c
}

// jsonObject returns the outermost JSON object in raw (vtysh can print a
// line before it), or an error when there is none: a failed CLI.
func jsonObject(raw string) ([]byte, error) {
	start, end := strings.Index(raw, "{"), strings.LastIndex(raw, "}")
	if start < 0 || end < start {
		return nil, errors.New("no JSON in input (CLI failed?)")
	}
	return []byte(raw[start : end+1]), nil
}

// FRR: `show bgp ipv4 unicast <prefix> json`; {} when the prefix is absent.
func parseFRR(prefix, raw string) ([]Path, error) {
	if strings.Contains(raw, "not in table") && !strings.Contains(raw, "{") {
		return nil, nil
	}
	doc, err := jsonObject(raw)
	if err != nil {
		return nil, err
	}
	var v struct {
		Prefix string `json:"prefix"`
		Paths  []struct {
			PeerID string `json:"peerId"`
			Peer   *struct {
				PeerID string `json:"peerId"`
			} `json:"peer"`
			LocPrf   *int            `json:"locPrf"`
			Bestpath json.RawMessage `json:"bestpath"`
			Nexthops []struct {
				IP string `json:"ip"`
			} `json:"nexthops"`
			Community *struct {
				String string   `json:"string"`
				List   []string `json:"list"`
			} `json:"community"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(doc, &v); err != nil {
		return nil, fmt.Errorf("frr: %w", err)
	}
	if v.Prefix != "" && v.Prefix != prefix {
		return nil, fmt.Errorf("frr: output is for %s, want %s", v.Prefix, prefix)
	}
	var out []Path
	for _, fp := range v.Paths {
		p := Path{From: fp.PeerID, LocalPref: -1}
		if fp.Peer != nil && fp.Peer.PeerID != "" {
			p.From = fp.Peer.PeerID
		}
		if fp.LocPrf != nil {
			p.LocalPref = *fp.LocPrf
		}
		if len(fp.Nexthops) > 0 {
			p.NextHop = fp.Nexthops[0].IP
		}
		var best struct {
			Overall bool `json:"overall"`
		}
		var flag bool
		if json.Unmarshal(fp.Bestpath, &best) == nil && best.Overall {
			p.Best = true
		} else if json.Unmarshal(fp.Bestpath, &flag) == nil && flag {
			p.Best = true
		}
		if fp.Community != nil {
			list := fp.Community.List
			if len(list) == 0 {
				list = strings.Fields(fp.Community.String)
			}
			for _, c := range list {
				p.Communities = append(p.Communities, community(c))
			}
		}
		out = append(out, p)
	}
	return out, nil
}

var (
	// "198.51.100.0/24      unicast [packeteer 22:50:07.930 from 192.0.2.10] * (100) [i]"
	// and the continuation lines that leave the prefix out.
	birdRoute = regexp.MustCompile(`^(\S+)?\s+(?:unicast|blackhole|unreachable|prohibited)\s+\[(\S+)[^\]]*?(?:\sfrom\s(\S+))?\]\s*(\*)?`)
	birdPair  = regexp.MustCompile(`\((\d+),\s*(\d+)\)`)
)

// BIRD 2 and 3: `show route all <prefix>`. BIRD 2 prints attributes as
// "BGP.next_hop: ..."; BIRD 3 as "bgp_next_hop: ..." plus "from: ...".
func parseBIRD(prefix, raw string) ([]Path, error) {
	if !strings.Contains(raw, "BIRD") && !strings.Contains(raw, "Table ") {
		return nil, errors.New("bird: not birdc output (CLI failed?)")
	}
	var out []Path
	var cur *Path
	current := ""
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := sc.Text()
		if m := birdRoute.FindStringSubmatch(line); m != nil && !strings.HasPrefix(line, "\t") {
			if m[1] != "" {
				current = m[1]
			}
			if current != prefix {
				cur = nil
				continue
			}
			out = append(out, Path{Proto: m[2], From: m[3], LocalPref: -1, Best: m[4] == "*"})
			cur = &out[len(out)-1]
			continue
		}
		if cur == nil {
			continue
		}
		key, val, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch strings.ToLower(strings.TrimPrefix(key, "BGP.")) {
		case "from":
			cur.From = val
		case "next_hop", "bgp_next_hop":
			cur.NextHop = strings.Fields(val + " ")[0]
		case "local_pref", "bgp_local_pref":
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("bird: local_pref %q", val)
			}
			cur.LocalPref = n
		case "community", "bgp_community":
			for _, m := range birdPair.FindAllStringSubmatch(val, -1) {
				cur.Communities = append(cur.Communities, m[1]+":"+m[2])
			}
		}
	}
	for i := range out {
		if out[i].From == "" {
			out[i].From = out[i].Proto
		}
	}
	return out, sc.Err()
}

// GoBGP: `gobgp global rib -a ipv4 <prefix> -j`; {} when absent.
func parseGoBGP(prefix, raw string) ([]Path, error) {
	doc, err := jsonObject(raw)
	if err != nil {
		return nil, err
	}
	var v map[string][]struct {
		Best     bool   `json:"best"`
		Neighbor string `json:"neighbor-ip"`
		Attrs    []struct {
			Type        int      `json:"type"`
			Value       *int     `json:"value"`
			Nexthop     string   `json:"nexthop"`
			Communities []uint32 `json:"communities"`
		} `json:"attrs"`
	}
	if err := json.Unmarshal(doc, &v); err != nil {
		return nil, fmt.Errorf("gobgp: %w", err)
	}
	var out []Path
	for _, gp := range v[prefix] {
		p := Path{From: gp.Neighbor, LocalPref: -1, Best: gp.Best}
		for _, a := range gp.Attrs {
			switch a.Type {
			case 3: // NEXT_HOP
				p.NextHop = a.Nexthop
			case 5: // LOCAL_PREF
				if a.Value != nil {
					p.LocalPref = *a.Value
				}
			case 8: // COMMUNITIES
				for _, c := range a.Communities {
					p.Communities = append(p.Communities, fmt.Sprintf("%d:%d", c>>16, c&0xffff))
				}
			}
		}
		out = append(out, p)
	}
	return out, nil
}
