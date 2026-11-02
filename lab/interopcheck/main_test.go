package main

import (
	"os"
	"strings"
	"testing"
)

const prefix = "198.51.100.0/24"

// The testdata files are real output: BIRD 2.17.5, BIRD 3.1.7, and GoBGP
// v3.37.0 peered with Packeteer in the lab topology; the FRR files have the
// shape of FRR 10.2's per-prefix JSON.
func load(t *testing.T, format, name string) []Path {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := Parse(format, prefix, string(raw))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return paths
}

func want(mode string) Want {
	return Want{Mode: mode, Peer: "192.0.2.10", Protocol: "packeteer", Community: "64512:666", NextHop: "192.0.2.22", LocalPref: 250}
}

func TestRouters(t *testing.T) {
	for _, tc := range []struct {
		format, injected, native string
	}{
		{"frr", "frr-injected.json", "frr-native.json"},
		{"bird", "bird-injected.txt", "bird-native.txt"},
		{"bird", "bird-addpath.txt", "bird-native.txt"},
		{"bird", "bird3-injected.txt", "bird3-native.txt"},
		{"gobgp", "gobgp-injected.json", "gobgp-native.json"},
	} {
		in := load(t, tc.format, tc.injected)
		if len(in) < 2 {
			t.Errorf("%s: %d paths, want the injected and the native ones", tc.injected, len(in))
		}
		if err := Check(in, want("injected")); err != nil {
			t.Errorf("%s injected: %v", tc.injected, err)
		}
		for _, mode := range []string{"native", "absent"} {
			if err := Check(in, want(mode)); err == nil {
				t.Errorf("%s: %s passed with Packeteer's route present", tc.injected, mode)
			}
		}
		nat := load(t, tc.format, tc.native)
		for _, mode := range []string{"native", "absent"} {
			if err := Check(nat, want(mode)); err != nil {
				t.Errorf("%s %s: %v", tc.native, mode, err)
			}
		}
		if err := Check(nat, want("injected")); err == nil {
			t.Errorf("%s: injected passed without Packeteer's route", tc.native)
		}
	}
}

func TestBIRDAttributes(t *testing.T) {
	for _, name := range []string{"bird-injected.txt", "bird3-injected.txt"} {
		paths := load(t, "bird", name)
		p := paths[0]
		if p.Proto != "packeteer" || p.From != "192.0.2.10" || !p.Best || p.NextHop != "192.0.2.22" || p.LocalPref != 250 ||
			strings.Join(p.Communities, " ") != "64512:666 65535:65281" {
			t.Errorf("%s: %+v", name, p)
		}
		for _, q := range paths[1:] {
			if q.Best || q.Proto == "packeteer" || q.LocalPref != 100 {
				t.Errorf("%s: native path %+v", name, q)
			}
		}
	}
}

func TestAbsentPrefix(t *testing.T) {
	for format, name := range map[string]string{"bird": "bird-none.txt", "gobgp": "gobgp-none.json"} {
		paths := load(t, format, name)
		if len(paths) != 0 {
			t.Errorf("%s: %+v", name, paths)
		}
		if err := Check(paths, want("absent")); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if err := Check(paths, want("native")); err == nil {
			t.Errorf("%s: native passed with no path at all", name)
		}
	}
	for _, raw := range []string{"{}", "% Network not in table"} {
		paths, err := Parse("frr", "203.0.113.0/24", raw)
		if err != nil || len(paths) != 0 {
			t.Errorf("frr %q: %v %v", raw, paths, err)
		}
	}
}

// A failed CLI must never read as "absent".
func TestUnreadable(t *testing.T) {
	for _, format := range []string{"frr", "bird", "gobgp"} {
		for _, raw := range []string{"", "Error response from daemon: container is not running\n"} {
			if _, err := Parse(format, prefix, raw); err == nil {
				t.Errorf("%s %q: parsed", format, raw)
			}
		}
	}
	if _, err := Parse("frr", prefix, `{"prefix":"203.0.113.0/24","paths":[]}`); err == nil {
		t.Error("frr output for another prefix was accepted")
	}
}

func TestOnlyThePrefix(t *testing.T) {
	// BIRD prints the matching prefix; a more-specific must not count.
	raw := "BIRD 2.17.5 ready.\nTable master4:\n" +
		"198.51.100.128/25    unicast [packeteer 22:50:07.930 from 192.0.2.10] * (100) [i]\n" +
		"\tBGP.next_hop: 192.0.2.22\n\tBGP.local_pref: 250\n\tBGP.community: (64512,666) (65535,65281)\n"
	paths, err := Parse("bird", prefix, raw)
	if err != nil || len(paths) != 0 {
		t.Fatalf("got %+v %v", paths, err)
	}
	paths, _ = Parse("bird", "198.51.100.128/25", raw)
	if err := Check(paths, want("absent")); err == nil {
		t.Error("absent passed with Packeteer's /25 in the table")
	}
}

func TestInjectedRejects(t *testing.T) {
	good := Path{From: "192.0.2.10", NextHop: "192.0.2.22", LocalPref: 250, Communities: []string{"64512:666", noExport}, Best: true}
	native := Path{From: "192.0.2.21", NextHop: "192.0.2.21", LocalPref: 100}
	for name, tc := range map[string]struct {
		paths []Path
		msg   string
	}{
		"not best":      {[]Path{{From: "192.0.2.10", NextHop: "192.0.2.22", LocalPref: 250, Communities: good.Communities}, {From: "192.0.2.21", Best: true}}, "not the best"},
		"next hop":      {[]Path{{From: "192.0.2.10", NextHop: "192.0.2.21", LocalPref: 250, Communities: good.Communities, Best: true}}, "next hop"},
		"local pref":    {[]Path{{From: "192.0.2.10", NextHop: "192.0.2.22", LocalPref: 100, Communities: good.Communities, Best: true}}, "local preference"},
		"no export":     {[]Path{{From: "192.0.2.10", NextHop: "192.0.2.22", LocalPref: 250, Communities: []string{"64512:666"}, Best: true}}, "no-export"},
		"untagged":      {[]Path{{From: "192.0.2.10", NextHop: "192.0.2.22", LocalPref: 250, Communities: []string{noExport}, Best: true}}, "community"},
		"two":           {[]Path{good, good}, "exactly 1"},
		"other speaker": {[]Path{{From: "192.0.2.30", NextHop: "192.0.2.22", LocalPref: 250, Communities: good.Communities, Best: true}}, "from"},
		"none":          {[]Path{native}, "exactly 1"},
	} {
		err := Check(tc.paths, want("injected"))
		if err == nil || !strings.Contains(err.Error(), tc.msg) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.msg)
		}
	}
	if err := Check([]Path{good, native}, want("injected")); err != nil {
		t.Error(err)
	}
}

// A static route from the external policy feed (#232) has no BGP next hop
// attribute: the next hop is the "via" gateway. The output is shaped like
// BIRD 2 and BIRD 3 print a static route with BGP attributes set.
func TestBIRDStaticFeedRoute(t *testing.T) {
	native := "                     unicast [transit_a 22:50:05.661] (100) [AS64496?]\n\tvia 192.0.2.21 on eth0\n\tBGP.next_hop: 192.0.2.21\n\tBGP.local_pref: 100\n"
	for name, raw := range map[string]string{
		"bird2": "BIRD 2.17.5 ready.\nTable master4:\n198.51.100.0/24      unicast [packeteer_feed4 22:50:07.930] * (200)\n\tvia 192.0.2.22 on eth0\n\tType: static univ\n\tBGP.local_pref: 250\n\tBGP.community: (64512,666) (65535,65281)\n" + native,
		"bird3": "BIRD 3.1.7 ready.\nTable master4:\n198.51.100.0/24      unicast [packeteer_feed4 22:53:49.421] * (200)\n\tvia 192.0.2.22 on eth0\n\tpreference: 200\n\tsource: static\n\tbgp_local_pref: 250\n\tbgp_community: (64512,666) (65535,65281)\n" + native,
	} {
		paths, err := Parse("bird", prefix, raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(paths) != 2 || paths[0].NextHop != "192.0.2.22" || paths[1].NextHop != "192.0.2.21" {
			t.Fatalf("%s: %+v", name, paths)
		}
		w := Want{Mode: "injected", Peer: "packeteer_feed4", Protocol: "packeteer_feed4", Community: "64512:666", NextHop: "192.0.2.22", LocalPref: 250}
		if err := Check(paths, w); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		w.NextHop = "192.0.2.21"
		if err := Check(paths, w); err == nil {
			t.Errorf("%s: injected passed with the wrong next hop", name)
		}
	}
}
