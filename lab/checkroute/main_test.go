package main

import (
	"encoding/json"
	"testing"
)

func TestCheckPresentAndAbsent(t *testing.T) {
	present := map[string]any{
		"routes": map[string]any{
			"198.51.100.0/24": []any{
				map[string]any{
					"locPrf":    float64(localPref),
					"nexthops":  []any{map[string]any{"ip": nextHop}},
					"community": map[string]any{"list": []any{community, "no-export"}},
				},
				map[string]any{"locPrf": float64(100), "nexthops": []any{map[string]any{"ip": "192.0.2.1"}}},
			},
		},
	}
	// FRR 10.2 summary JSON has next hop and local-pref but no community.
	summary := map[string]any{
		"routes": map[string]any{
			"198.51.100.0/24": []any{
				map[string]any{"locPrf": float64(localPref), "nexthops": []any{map[string]any{"ip": nextHop}}},
			},
		},
	}
	summaryText := mustJSON(summary) + `
BGP routing table entry for 198.51.100.0/24
    192.0.2.2 from 192.0.2.10 (192.0.2.10)
      Origin IGP, localpref 250, valid, internal
      Community: 64512:666 no-export
`
	absent := map[string]any{
		"routes": map[string]any{
			"198.51.100.0/24": []any{
				map[string]any{"locPrf": float64(100), "nexthops": []any{map[string]any{"ip": "192.0.2.1"}}},
			},
		},
	}
	nativeText := mustJSON(absent) + `
BGP routing table entry for 198.51.100.0/24
    192.0.2.1 from 0.0.0.0 (192.0.2.254)
      Origin IGP, metric 0, weight 32768, valid, sourced, local, best
`
	pathsShape := `{
  "198.51.100.0/24": {
    "paths": [{
      "localPref": 250,
      "nexthop": "192.0.2.2",
      "community": {"string": "64512:666 no-export"}
    }]
  }
}`

	cases := []struct {
		name    string
		raw     string
		present bool
		absent  bool
	}{
		{"json with community", mustJSON(present), true, false},
		{"summary json plus detail text", summaryText, true, false},
		{"summary json alone is not injected", mustJSON(summary), false, true},
		{"native route only", mustJSON(absent), false, true},
		{"native route detail text", nativeText, false, true},
		{"detail text alone", summaryText[len(mustJSON(summary)):], true, false},
		{"paths object and community string", pathsShape, true, false},
		{"no-export anywhere is not absent", nativeText + "\nno-export\n", false, false},
		{"empty input is not present and looks absent", "", false, true},
		{"broken json falls through to text", "not-json " + summaryText[len(mustJSON(summary)):], true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := check("present", tc.raw); got != tc.present {
				t.Errorf("present = %v, want %v", got, tc.present)
			}
			if got := check("absent", tc.raw); got != tc.absent {
				t.Errorf("absent = %v, want %v", got, tc.absent)
			}
		})
	}
}

func TestCommunitiesLowercased(t *testing.T) {
	raw := mustJSON(map[string]any{
		"locPrf":    float64(localPref),
		"nexthops":  []any{map[string]any{"ip": nextHop}},
		"community": map[string]any{"list": []any{"64512:666", "NO-EXPORT"}},
	})
	if !check("present", raw) {
		t.Fatal("uppercase NO-EXPORT in JSON was not accepted")
	}
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}
