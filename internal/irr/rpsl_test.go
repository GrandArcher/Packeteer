package irr

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func parseAll(t *testing.T, text string) []Object {
	t.Helper()
	var out []Object
	if err := ParseRPSL(strings.NewReader(text), func(o Object) error { out = append(out, o); return nil }); err != nil {
		t.Fatal(err)
	}
	return out
}

// #214: objects split on blank lines; % lines, comments, and continuation
// lines (space, tab, +) follow RFC 2622.
func TestParseRPSL(t *testing.T) {
	objs := parseAll(t, "% header\n\nRoute:  198.51.100.0/24 # comment\norigin: AS64496\nremarks: first\n second\n\t third\n+\nsource: RADB\n\n\n# lone comment\nas-set: AS-EXAMPLE\nmembers: AS64496,\n+ AS64497\n")
	if len(objs) != 2 {
		t.Fatalf("objects = %d, want 2", len(objs))
	}
	if objs[0].Class() != "route" || objs[0][0].Value != "198.51.100.0/24" || objs[0].Get("remarks") != "first second third" || objs[0].Get("source") != "RADB" {
		t.Fatalf("route = %+v", objs[0])
	}
	if got := objs[1].All("members"); !slices.Equal(got, []string{"AS64496, AS64497"}) {
		t.Fatalf("members = %q", got)
	}
	if err := ParseRPSL(strings.NewReader("route 198.51.100.0/24\n"), func(Object) error { return nil }); err == nil {
		t.Fatal("a line without a colon parsed")
	}
	stop := errors.New("stop")
	if err := ParseRPSL(strings.NewReader("a: 1\n\nb: 2\n"), func(Object) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("callback error = %v", err)
	}
}

func TestRoute(t *testing.T) {
	objs := parseAll(t, "route6: 2001:DB8::/32\norigin: as64496\nsource: radb\n\nroute: 203.0.113.0/24\norigin: AS64499\nsource: RPKI  # Trust Anchor: ripe\n\nroute: bogus\norigin: AS1\n\naut-num: AS64496\n")
	rt, ok := Route(objs[0])
	if !ok || rt != (plugin.IRRRoute{Prefix: netip.MustParsePrefix("2001:db8::/32"), Origin: 64496, Database: "RADB"}) {
		t.Fatalf("route6 = %+v %v", rt, ok)
	}
	for _, o := range objs[1:] {
		if _, ok := Route(o); ok {
			t.Errorf("%v read as a route", o)
		}
	}
}

func TestASSetNames(t *testing.T) {
	for name, want := range map[string]bool{
		"AS-EXAMPLE": true, "as-example": true, "AS64500:AS-CUSTOMERS": true, "AS-A:AS-B:AS64501": true,
		"AS64500": false, "AS-ANY": false, "EXAMPLE": false, "AS-": false, "AS64500:AS65": false, "AS-EX AMPLE": false,
	} {
		if got := ValidASSetName(name); got != want {
			t.Errorf("ValidASSetName(%q) = %v", name, got)
		}
	}
	objs := parseAll(t, "as-set: AS-EXAMPLE\nmembers: AS64496, AS-NESTED AS64497\nmembers: RS-EXAMPLE, AS-ANY, 64498\n")
	asns, sets := Members(objs[0])
	if !slices.Equal(asns, []uint32{64496, 64497}) || !slices.Equal(sets, []string{"AS-NESTED"}) {
		t.Fatalf("members = %v %v", asns, sets)
	}
}

// Expand visits each set once, so a loop ends, and stops at its bounds.
func TestExpand(t *testing.T) {
	sets := map[string][2][]string{
		"AS-A": {{"64496"}, {"AS-B", "AS-MISSING"}},
		"AS-B": {{"64497", "64496"}, {"AS-A"}},
	}
	asked := 0
	members := func(name string) ([]uint32, []string, bool, error) {
		asked++
		s, ok := sets[name]
		var asns []uint32
		for _, a := range s[0] {
			var n uint32
			fmt.Sscan(a, &n)
			asns = append(asns, n)
		}
		return asns, s[1], ok, nil
	}
	got, err := Expand("AS-A", members)
	if err != nil || !slices.Equal(got, []uint32{64496, 64497}) || asked != 3 {
		t.Fatalf("Expand = %v %v asked %d", got, err, asked)
	}
	deep := func(name string) ([]uint32, []string, bool, error) {
		return nil, []string{name + "X"}, true, nil
	}
	if _, err := Expand("AS-D", deep); !errors.Is(err, ErrSetTooLarge) {
		t.Fatalf("deep chain err = %v", err)
	}
	fail := errors.New("down")
	if _, err := Expand("AS-A", func(string) ([]uint32, []string, bool, error) { return nil, nil, false, fail }); !errors.Is(err, fail) {
		t.Fatalf("lookup error = %v", err)
	}
}
