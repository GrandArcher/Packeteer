package flow

import (
	"net/netip"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/passive"
)

func TestMappedExporterPrefixes(t *testing.T) {
	for _, tc := range []struct{ prefix, inside, outside string }{
		{"::ffff:192.0.2.0/120", "192.0.2.42", "192.0.3.42"},
		{"::ffff:192.0.2.1/128", "192.0.2.1", "192.0.2.2"},
		{"::ffff:0.0.0.0/96", "192.0.2.1", "2001:db8::1"},
		{"2001:db8::/64", "2001:db8::1", "2001:db8:1::1"},
	} {
		t.Run(tc.prefix, func(t *testing.T) {
			s := mustSource(t, "listen: 127.0.0.1:0\nexporters: ['"+tc.prefix+"']\n")
			if !passive.Contains(s.exporters, netip.MustParseAddr(tc.inside)) {
				t.Errorf("%v does not contain %s", s.exporters, tc.inside)
			}
			if passive.Contains(s.exporters, netip.MustParseAddr(tc.outside)) {
				t.Errorf("%v contains %s", s.exporters, tc.outside)
			}
		})
	}
	for _, in := range [][]string{
		{"::ffff:192.0.2.1/120"},
		{"::ffff:0.0.0.0/95"},
		{"::ffff:192.0.2.0/120", "192.0.2.0/24"},
		{"::ffff:192.0.2.1/128", "192.0.2.1"},
	} {
		if _, err := parseExporters(in); err == nil {
			t.Errorf("accepted invalid exporters %v", in)
		}
	}
}
