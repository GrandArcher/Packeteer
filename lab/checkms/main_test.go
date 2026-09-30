package main

import (
	"slices"
	"testing"
)

func TestFromPacketeer(t *testing.T) {
	raw := `vtysh noise
{"vrfId":0,"routerId":"192.0.2.254","defaultLocPrf":100,"localAS":64512,"routes":{
 "198.51.100.0/24":[
  {"valid":true,"bestpath":true,"network":"198.51.100.0/24","weight":32768,"peerId":"(unspec)","nexthops":[{"ip":"0.0.0.0"}]},
  {"valid":true,"network":"198.51.100.0/24","locPrf":250,"weight":0,"peerId":"192.0.2.10","nexthops":[{"ip":"192.0.2.2"}]}],
 "198.51.100.0/25":[
  {"valid":true,"bestpath":true,"network":"198.51.100.0/25","weight":32768,"peerId":"(unspec)","nexthops":[{"ip":"0.0.0.0"}]},
  {"valid":true,"network":"198.51.100.0/25","locPrf":250,"nexthops":[{"ip":"192.0.2.2"}]}],
 "203.0.113.0/24":[
  {"valid":true,"bestpath":true,"network":"203.0.113.0/24","weight":32768,"peerId":"(unspec)","nexthops":[{"ip":"0.0.0.0"}]}]
}}`
	got, err := fromPacketeer([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"198.51.100.0/24", "198.51.100.0/25"}; !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	got, err = fromPacketeer([]byte(`{"vrfId":0,"routes":{}}`))
	if err != nil || len(got) != 0 {
		t.Fatalf("empty table = %v, %v", got, err)
	}
	for _, bad := range []string{"", "% BGP instance not found", `{"vrfId":0}`, "{not json}"} {
		if _, err := fromPacketeer([]byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
