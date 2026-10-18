package configedit

import (
	"reflect"
	"strings"
	"testing"
)

func str(s string) *string { return &s }

func TestDiffNamesKeyOldAndNew(t *testing.T) {
	old := injectYAML
	next := strings.Replace(old, "hold_time: 5m", "hold_time: 2m", 1)
	next = strings.Replace(next, "next_hop: 192.0.2.2", "next_hop: 192.0.2.3", 1)
	next = strings.Replace(next, "prefixes: [198.51.100.0/24]", "prefixes: [198.51.100.0/24, 203.0.113.0/24]", 1)
	next = strings.Replace(next, "local_pref: 250\n", "", 1)
	got := Diff([]byte(old), []byte(next))
	want := []Change{
		{Key: "allowlist.prefixes[1]", New: str("203.0.113.0/24")},
		{Key: "hold_time", Old: str("5m"), New: str("2m")},
		{Key: "local_pref", Old: str("250")},
		{Key: "providers[1].next_hop", Old: str("192.0.2.2"), New: str("192.0.2.3")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("diff = %+v\nwant %+v", got, want)
	}
}

func TestDiffIgnoresCommentsAndFormatting(t *testing.T) {
	next := "# note\n" + strings.Replace(injectYAML, "thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}", "thresholds:\n  min_loss_delta_pct: 1\n  min_rtt_delta_ms: 15", 1)
	if got := Diff([]byte(injectYAML), []byte(next)); len(got) != 0 {
		t.Fatalf("diff = %+v, want none", got)
	}
}

func TestDiffFollowsAliases(t *testing.T) {
	old := "a: &x 1m\nb: *x\n"
	got := Diff([]byte(old), []byte("a: &x 2m\nb: *x\n"))
	want := []Change{{Key: "a", Old: str("1m"), New: str("2m")}, {Key: "b", Old: str("1m"), New: str("2m")}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("diff = %+v", got)
	}
}

func TestSaveReportsChanges(t *testing.T) {
	e, _ := editor(t, injectYAML)
	next := strings.Replace(injectYAML, "hold_time: 5m", "hold_time: 2m", 1)
	_, res, err := e.Save([]byte(next), Hash([]byte(injectYAML)), true)
	if err != nil {
		t.Fatal(err)
	}
	want := []Change{{Key: "hold_time", Old: str("5m"), New: str("2m")}}
	if !reflect.DeepEqual(res.Changes, want) {
		t.Fatalf("changes = %+v", res.Changes)
	}
	_, res, err = e.Save([]byte(next), Hash([]byte(next)), true)
	if err != nil || len(res.Changes) != 0 {
		t.Fatalf("unchanged save: %+v %v", res.Changes, err)
	}
}
