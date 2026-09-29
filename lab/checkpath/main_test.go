package main

import (
	"strings"
	"testing"
)

// Shape of FRR 10.2 `show bgp ipv4 unicast 203.0.113.0/24 json` on a transit.
const steered = `{
  "prefix":"203.0.113.0/24",
  "paths":[
    {
      "aspath":{"string":"64512 64512 64512","segments":[{"type":"as-sequence","list":[64512,64512,64512]}],"length":3},
      "origin":"IGP",
      "valid":true,
      "bestpath":{"overall":true,"selectionReason":"First path received"},
      "community":{"string":"64496:3","list":["64496:3"]},
      "nexthops":[{"ip":"192.0.2.254","afi":"ipv4","used":true}]
    }
  ]
}`

const plain = `{"prefix":"203.0.113.0/24","paths":[{"aspath":{"string":"64512","length":1},"valid":true,"bestpath":{"overall":true}}]}`

func TestCheck(t *testing.T) {
	steer := Want{ASPath: "64512 64512 64512", Has: []string{"64496:3"}, Lacks: []string{"64512:", "no-export"}}
	if err := Check("vtysh noise\n"+steered, steer); err != nil {
		t.Fatalf("steered: %v", err)
	}
	clean := Want{ASPath: "64512", Lacks: []string{"64512:", "64496:", "64497:"}}
	if err := Check(plain, clean); err != nil {
		t.Fatalf("plain: %v", err)
	}
	gone := Want{Absent: true}
	for _, raw := range []string{"{}", `{"prefix":"203.0.113.0/24","paths":[]}`, "% Network not in table"} {
		if err := Check(raw, gone); err != nil {
			t.Fatalf("absent %q: %v", raw, err)
		}
	}
	cases := map[string]struct {
		raw  string
		want Want
		msg  string
	}{
		"prepend missing":  {plain, steer, "as path"},
		"still prepended":  {steered, clean, "as path"},
		"te leaked":        {steered, Want{ASPath: "64512 64512 64512", Lacks: []string{"64496:"}}, "must not reach"},
		"community absent": {plain, Want{ASPath: "64512", Has: []string{"64496:3"}}, "missing"},
		"no json":          {"% Network not in table", clean, "no JSON"},
		"no paths":         {`{"prefix":"203.0.113.0/24","paths":[]}`, clean, "no paths"},
		"still announced":  {plain, gone, "want none"},
		"empty output":     {"", gone, "vtysh failed"},
		"no best":          {`{"paths":[{"aspath":{"string":"64512"}},{"aspath":{"string":"64512"}}]}`, clean, "no best"},
	}
	for name, tc := range cases {
		err := Check(tc.raw, tc.want)
		if err == nil || !strings.Contains(err.Error(), tc.msg) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.msg)
		}
	}
}

// Packeteer's route on the edge is locally originated (empty AS path); the
// BMP lab checks it by community alone.
func TestCheckCommunityOnly(t *testing.T) {
	injected := `{"prefix":"198.51.100.0/24","paths":[
	  {"aspath":{"string":"","length":0},"valid":true,"bestpath":{"overall":true},"community":{"string":"64512:666 noExport","list":["64512:666","noExport"]}},
	  {"aspath":{"string":"64496","length":1},"valid":true}]}`
	if err := Check(injected, Want{Has: []string{"64512:666"}}); err != nil {
		t.Fatalf("injected: %v", err)
	}
	native := `{"prefix":"198.51.100.0/24","paths":[{"aspath":{"string":"64496","length":1},"valid":true,"bestpath":{"overall":true}}]}`
	if err := Check(native, Want{Has: []string{"64512:666"}}); err == nil {
		t.Fatal("native best path passed a community check")
	}
}

// The multi-router lab (#27) checks which next hop each edge got.
func TestCheckNextHop(t *testing.T) {
	injected := `{"prefix":"198.51.100.0/24","paths":[
	  {"aspath":{"string":"","length":0},"valid":true,"bestpath":{"overall":true},"community":{"string":"64512:666 noExport","list":["64512:666","noExport"]},"nexthops":[{"ip":"192.0.2.252","afi":"ipv4","used":true}]},
	  {"aspath":{"string":"64496","length":1},"valid":true,"nexthops":[{"ip":"192.0.2.21","afi":"ipv4","used":true}]}]}`
	if err := Check(injected, Want{Has: []string{"64512:666"}, NextHop: "192.0.2.252"}); err != nil {
		t.Fatalf("via edge-b: %v", err)
	}
	if err := Check(injected, Want{Has: []string{"64512:666"}, NextHop: "192.0.2.22"}); err == nil || !strings.Contains(err.Error(), "next hop") {
		t.Fatalf("wrong next hop passed: %v", err)
	}
}

// FRR prints well-known communities by name; either spelling matches.
func TestCheckWellKnownCommunities(t *testing.T) {
	const rtbh = `{"prefix":"198.51.100.0/24","paths":[{"aspath":{"string":"","length":0},"valid":true,"bestpath":{"overall":true},
"community":{"string":"64512:666 64512:668 blackhole noExport","list":["64512:666","64512:668","blackhole","no-export"]},
"nexthops":[{"ip":"192.0.2.66","afi":"ipv4","used":true}]}]}`
	for _, w := range []Want{
		{NextHop: "192.0.2.66", Has: []string{"65535:666", "64512:668", "65535:65281"}},
		{NextHop: "192.0.2.66", Has: []string{"blackhole", "no-export"}},
	} {
		if err := Check(rtbh, w); err != nil {
			t.Fatalf("%+v: %v", w, err)
		}
	}
	// FRR 10.2 JSON as seen in the lab: "noExport" in the list.
	frr := strings.Replace(rtbh, `"no-export"]`, `"noExport"]`, 1)
	if err := Check(frr, Want{Has: []string{"no-export", "65535:65281"}}); err != nil {
		t.Fatalf("noExport: %v", err)
	}
	if err := Check(frr, Want{Has: []string{"64512:666"}, Lacks: []string{"no-export"}}); err == nil {
		t.Fatal("lacks no-export matched a noExport path")
	}
	if err := Check(rtbh, Want{Has: []string{"64512:668"}, Lacks: []string{"65535:666"}}); err == nil {
		t.Fatal("lacks 65535:666 matched a blackhole path")
	}
}
