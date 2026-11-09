package config

import (
	"strings"
	"testing"
)

const sharedBase = `
mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
`

func TestSharedSourceIPNeedsDistinctTags(t *testing.T) {
	for _, tc := range []struct {
		name, providers, want string
	}{
		{"dscp", `
  - {name: a, source_ip: 192.0.2.31, next_hop: 203.0.113.11, dscp: 10}
  - {name: b, source_ip: 192.0.2.31, next_hop: 203.0.113.12, dscp: 12}
`, ""},
		{"fwmark", `
  - {name: a, source_ip: 192.0.2.31, next_hop: 203.0.113.11, fwmark: 101}
  - {name: b, source_ip: 192.0.2.31, next_hop: 203.0.113.12, fwmark: 102}
`, ""},
		{"untagged second", `
  - {name: a, source_ip: 192.0.2.31, next_hop: 203.0.113.11, dscp: 10}
  - {name: b, source_ip: 192.0.2.31, next_hop: 203.0.113.12}
`, "providers[1] (b): duplicate source_ip 192.0.2.31"},
		{"untagged first", `
  - {name: a, source_ip: 192.0.2.31, next_hop: 203.0.113.11}
  - {name: b, source_ip: 192.0.2.31, next_hop: 203.0.113.12, dscp: 10}
`, "providers[1] (b): duplicate source_ip 192.0.2.31"},
		{"both untagged", `
  - {name: a, source_ip: 192.0.2.31, next_hop: 203.0.113.11}
  - {name: b, source_ip: 192.0.2.31, next_hop: 203.0.113.12}
`, "duplicate source_ip 192.0.2.31"},
		{"same dscp", `
  - {name: a, source_ip: 192.0.2.31, next_hop: 203.0.113.11, dscp: 10}
  - {name: b, source_ip: 192.0.2.31, next_hop: 203.0.113.12, dscp: 10}
`, "dscp 10 is already used by a on source_ip 192.0.2.31"},
		{"same fwmark", `
  - {name: a, source_ip: 192.0.2.31, next_hop: 203.0.113.11, fwmark: 7}
  - {name: b, source_ip: 192.0.2.31, next_hop: 203.0.113.12, fwmark: 7, dscp: 5}
`, "fwmark 7 is already used by a"},
		{"same dscp on another source", `
  - {name: a, source_ip: 192.0.2.31, next_hop: 203.0.113.11, dscp: 10}
  - {name: b, source_ip: 192.0.2.32, next_hop: 203.0.113.12, dscp: 10}
`, ""},
		{"dscp range", `
  - {name: a, source_ip: 192.0.2.31, next_hop: 203.0.113.11, dscp: 64}
`, "dscp 64 must be between 0 and 63"},
		{"remote", `
  - {name: a, source_ip: 192.0.2.31, next_hop: 203.0.113.11}
  - {name: b, next_hop: 203.0.113.12, domain: pop-b, dscp: 10}
`, "fwmark and dscp must be empty for a provider in domain pop-b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(sharedBase + tc.providers))
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestExchangePeersShareSourceByTag(t *testing.T) {
	yaml := strings.Replace(exchangeYAML, "source_ip: 192.0.2.32", "source_ip: 192.0.2.31\n        dscp: 12", 1)
	yaml = strings.Replace(yaml, "source_ip: 192.0.2.31\n      - name", "source_ip: 192.0.2.31\n        dscp: 10\n      - name", 1)
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	a, b := cfg.Providers[1], cfg.Providers[2]
	if a.SourceIP != b.SourceIP || a.DSCP != 10 || b.DSCP != 12 {
		t.Fatalf("peers = %+v %+v", a, b)
	}
	untagged := strings.Replace(exchangeYAML, "source_ip: 192.0.2.32", "source_ip: 192.0.2.31", 1)
	if _, err := Parse([]byte(untagged)); err == nil || !strings.Contains(err.Error(), "duplicate source_ip 192.0.2.31") {
		t.Fatalf("untagged shared peers: %v", err)
	}
}
