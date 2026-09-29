// Command checkpath checks the best path of one prefix in FRR's
// `show bgp ipv4 unicast <prefix> json` output. lab/e2e-inbound.sh runs it
// against the simulated transits to see which session got the prepend and
// the TE communities.
//
//	checkpath -aspath "64512 64512 64512" -has 64496:3 -lacks 64512: -lacks no-export
//
// -aspath may be left out when -has is given (a locally originated path,
// such as Packeteer's injected route on the edge, has an empty AS path).
// -has needs an exact community. -lacks rejects any community that starts
// with the value. -nexthop requires that next hop on the best path. -absent instead passes only when the prefix has no path
// (a selective announcement withheld it from this session). The exit status is 0 when the best path matches, 1 when it
// does not (the reason goes to stderr), and 2 on bad usage.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

// Want is what the best path must look like.
type Want struct {
	Absent  bool
	ASPath  string
	NextHop string
	Has     []string
	Lacks   []string
}

func main() {
	var w Want
	var has, lacks list
	fs := flag.NewFlagSet("checkpath", flag.ContinueOnError)
	fs.BoolVar(&w.Absent, "absent", false, "the prefix must have no path")
	fs.StringVar(&w.ASPath, "aspath", "", "exact AS path string of the best path")
	fs.StringVar(&w.NextHop, "nexthop", "", "next hop the best path must use")
	fs.Var(&has, "has", "community the best path must carry (repeatable)")
	fs.Var(&lacks, "lacks", "community prefix the best path must not carry (repeatable)")
	if err := fs.Parse(os.Args[1:]); err != nil || (w.ASPath == "" && len(has) == 0) == !w.Absent {
		fmt.Fprintln(os.Stderr, "usage: checkpath [-aspath PATH] [-has C]... [-lacks PREFIX]... [-nexthop IP] | checkpath -absent")
		os.Exit(2)
	}
	w.Has, w.Lacks = has, lacks
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := Check(string(raw), w); err != nil {
		fmt.Fprintln(os.Stderr, "checkpath:", err)
		os.Exit(1)
	}
}

type path struct {
	ASPath struct {
		String string `json:"string"`
	} `json:"aspath"`
	Community *struct {
		String string   `json:"string"`
		List   []string `json:"list"`
	} `json:"community"`
	Bestpath *struct {
		Overall bool `json:"overall"`
	} `json:"bestpath"`
	Nexthops []struct {
		IP string `json:"ip"`
	} `json:"nexthops"`
}

// Check reports why the best path in raw does not match w, or nil.
func Check(raw string, w Want) error {
	start, end := strings.Index(raw, "{"), strings.LastIndex(raw, "}")
	if w.Absent {
		// FRR prints {} (or "Network not in table") for a prefix it does
		// not have. Empty output is a failed vtysh, not an absent prefix.
		if start < 0 || end < start {
			if strings.Contains(raw, "not in table") {
				return nil
			}
			return errors.New("no JSON in input (vtysh failed?)")
		}
		var doc struct {
			Paths []json.RawMessage `json:"paths"`
		}
		if err := json.Unmarshal([]byte(raw[start:end+1]), &doc); err != nil {
			return fmt.Errorf("parse: %w", err)
		}
		if len(doc.Paths) != 0 {
			return fmt.Errorf("prefix has %d paths, want none", len(doc.Paths))
		}
		return nil
	}
	if start < 0 || end < start {
		return errors.New("no JSON in input (prefix not in the table?)")
	}
	var doc struct {
		Paths []path `json:"paths"`
	}
	if err := json.Unmarshal([]byte(raw[start:end+1]), &doc); err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	if len(doc.Paths) == 0 {
		return errors.New("prefix has no paths")
	}
	best := -1
	for i, p := range doc.Paths {
		if p.Bestpath != nil && p.Bestpath.Overall {
			best = i
			break
		}
	}
	if best < 0 {
		if len(doc.Paths) != 1 {
			return errors.New("no best path")
		}
		best = 0
	}
	p := doc.Paths[best]
	if got := strings.TrimSpace(p.ASPath.String); w.ASPath != "" && got != w.ASPath {
		return fmt.Errorf("as path %q, want %q", got, w.ASPath)
	}
	if w.NextHop != "" {
		var got []string
		for _, nh := range p.Nexthops {
			got = append(got, nh.IP)
		}
		if !slices.Contains(got, w.NextHop) {
			return fmt.Errorf("next hop %v, want %s", got, w.NextHop)
		}
	}
	var comms []string
	if p.Community != nil {
		comms = append(comms, p.Community.List...)
		if len(comms) == 0 {
			comms = strings.Fields(p.Community.String)
		}
	}
	for i := range comms {
		comms[i] = strings.ToLower(comms[i])
	}
	for _, h := range w.Has {
		found := false
		for _, c := range comms {
			if c == strings.ToLower(h) {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("community %s missing (have %v)", h, comms)
		}
	}
	for _, l := range w.Lacks {
		for _, c := range comms {
			if strings.HasPrefix(c, strings.ToLower(l)) {
				return fmt.Errorf("community %s must not reach this session (have %v)", c, comms)
			}
		}
	}
	return nil
}
