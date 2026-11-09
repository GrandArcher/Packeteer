package main

import (
	"reflect"
	"testing"
)

func TestFromPeer(t *testing.T) {
	raw := []byte(`edge-a# {"routes":{
"198.51.100.0/24":[
  {"peerId":"192.0.2.10","locPrf":250,"nexthops":[{"ip":"192.0.2.253"}]},
  {"peerId":"(unspec)","nexthops":[{"ip":"0.0.0.0"}]}],
"203.0.113.0/24":[{"peerId":"(unspec)","nexthops":[{"ip":"0.0.0.0"}]}]}}`)
	got, err := fromPeer(raw, "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"198.51.100.0/24 192.0.2.253"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	got, err = fromPeer([]byte(`{"routes":{}}`), "192.0.2.10")
	if err != nil || len(got) != 0 {
		t.Fatalf("empty table: %v %v", got, err)
	}
	for _, bad := range []string{"", "% no bgp", `{"vrfId":0}`} {
		if _, err := fromPeer([]byte(bad), "192.0.2.10"); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
