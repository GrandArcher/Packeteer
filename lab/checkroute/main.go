// Command checkroute reports whether FRR's BGP table still has Packeteer's
// injected route. lab/e2e.sh pipes `show bgp ipv4 unicast` text and JSON
// into it. FRR 10.2's summary JSON omits communities, so the detail text
// line is accepted as well.
//
// Constants match lab/packeteer.yaml and the lab prefix. localPref is the
// global value; lab/e2e.sh overrides it with local_pref_cause.performance.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const (
	nextHop   = "192.0.2.2"
	community = "64512:666"
	localPref = 250
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 || (os.Args[1] != "present" && os.Args[1] != "absent") {
		fmt.Fprintln(os.Stderr, "usage: checkroute present|absent [local_pref]")
		os.Exit(2)
	}
	wantPref := localPref
	if len(os.Args) == 3 {
		n, err := strconv.Atoi(os.Args[2])
		if err != nil || n <= 0 {
			fmt.Fprintf(os.Stderr, "invalid local_pref %q\n", os.Args[2])
			os.Exit(2)
		}
		wantPref = n
	}
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if checkAt(os.Args[1], string(raw), wantPref) {
		os.Exit(0)
	}
	os.Exit(1)
}

// check reports whether mode ("present" or "absent") holds for raw vtysh
// output at the default local preference 250. present requires next hop
// 192.0.2.2, that local preference, community 64512:666, and no-export.
// absent requires that community to be gone; the router's own copy of the
// prefix may remain. The commit and cost labs call this with no override.
func check(mode, raw string) bool {
	return checkAt(mode, raw, localPref)
}

// checkAt is check with an explicit local preference. lab/e2e.sh passes
// 260 (local_pref_cause.performance) so the main lab can require a value
// distinct from the global 250 without changing the commit and cost labs.
func checkAt(mode, raw string, wantPref int) bool {
	paths := walk(load(raw))
	jsonFull := false
	jsonNH := false
	for _, p := range paths {
		if isInjected(p, wantPref) {
			jsonFull = true
		}
		if nhAndPref(p, wantPref) {
			jsonNH = true
		}
	}
	if mode == "present" {
		// textHasInjected covers FRR 10.2, whose summary JSON has the next
		// hop and local preference but no community object. The detail text
		// prints 64512:666 and no-export. Extra communities may sit between
		// them, so those two tokens are matched apart.
		return jsonFull || (jsonNH && textHasInjected(raw, wantPref)) || textHasInjected(raw, wantPref)
	}
	for _, p := range paths {
		if hasPacketeer(p) {
			return false
		}
	}
	return !textHasCommunity(raw)
}

func load(text string) any {
	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start < 0 || end < start {
		return nil
	}
	var v any
	if err := json.Unmarshal([]byte(text[start:end+1]), &v); err != nil {
		return nil
	}
	return v
}

func walk(obj any) []map[string]any {
	var out []map[string]any
	var rec func(any)
	rec = func(obj any) {
		switch v := obj.(type) {
		case map[string]any:
			if _, ok := v["nexthops"]; ok {
				out = append(out, v)
			} else if _, ok := v["community"]; ok {
				out = append(out, v)
			} else if _, ok := v["locPrf"]; ok {
				out = append(out, v)
			} else if _, ok := v["localPref"]; ok {
				out = append(out, v)
			}
			for _, child := range v {
				rec(child)
			}
		case []any:
			for _, child := range v {
				rec(child)
			}
		}
	}
	rec(obj)
	return out
}

func nexthops(path map[string]any) []string {
	var out []string
	for _, key := range []string{"nexthops", "nextHops", "nexthop"} {
		val, ok := path[key]
		if !ok || val == nil {
			continue
		}
		switch v := val.(type) {
		case []any:
			for _, item := range v {
				switch it := item.(type) {
				case map[string]any:
					if ip, ok := it["ip"].(string); ok {
						out = append(out, ip)
					}
				case string:
					out = append(out, it)
				}
			}
		case string:
			out = append(out, v)
		}
	}
	return out
}

func localPrefOf(path map[string]any) (int, bool) {
	for _, key := range []string{"locPrf", "localPref", "localpref", "localPreference"} {
		val, ok := path[key]
		if !ok || val == nil {
			continue
		}
		switch n := val.(type) {
		case float64:
			return int(n), true
		case json.Number:
			i, err := n.Int64()
			if err != nil {
				return 0, false
			}
			return int(i), true
		case string:
			i, err := strconv.Atoi(n)
			if err != nil {
				return 0, false
			}
			return i, true
		default:
			return 0, false
		}
	}
	return 0, false
}

func communities(path map[string]any) []string {
	var found []string
	for _, key := range []string{"community", "communities"} {
		c, ok := path[key]
		if !ok || c == nil {
			continue
		}
		switch v := c.(type) {
		case map[string]any:
			if list, ok := v["list"].([]any); ok {
				for _, item := range list {
					found = append(found, fmt.Sprint(item))
				}
			}
			if s, ok := v["string"].(string); ok {
				found = append(found, strings.Fields(s)...)
			}
		case []any:
			for _, item := range v {
				found = append(found, fmt.Sprint(item))
			}
		case string:
			found = append(found, strings.Fields(v)...)
		}
	}
	for i, s := range found {
		found[i] = strings.ToLower(s)
	}
	return found
}

func hasPacketeer(path map[string]any) bool {
	return contains(communities(path), community)
}

func isInjected(path map[string]any, wantPref int) bool {
	comms := communities(path)
	lp, ok := localPrefOf(path)
	return ok && contains(nexthops(path), nextHop) && lp == wantPref && contains(comms, community) && (contains(comms, "no-export") || contains(comms, "no_export"))
}

func nhAndPref(path map[string]any, wantPref int) bool {
	lp, ok := localPrefOf(path)
	return ok && contains(nexthops(path), nextHop) && lp == wantPref
}

func textHasInjected(text string, wantPref int) bool {
	return strings.Contains(text, "192.0.2.2 from 192.0.2.10") &&
		strings.Contains(text, "localpref "+strconv.Itoa(wantPref)) &&
		strings.Contains(text, "64512:666") &&
		strings.Contains(text, "no-export")
}

func textHasCommunity(text string) bool {
	return strings.Contains(text, "64512:666") || strings.Contains(text, "no-export")
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
