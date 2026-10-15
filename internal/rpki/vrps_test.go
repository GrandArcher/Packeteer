package rpki

import (
	"net/netip"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func p(t *testing.T, s string) netip.Prefix {
	t.Helper()
	return netip.MustParsePrefix(s)
}

// #158: RFC 6811 origin validation: valid when a covering payload
// authorizes the origin, invalid when covered but unmatched, not-found
// when nothing covers.
func TestVRPsValidate(t *testing.T) {
	table := NewVRPs()
	table.Add(p(t, "198.51.100.0/24"), 24, 64500)
	table.Add(p(t, "203.0.113.0/24"), 26, 64501)
	table.Add(p(t, "2001:db8::/32"), 48, 64502)

	tests := []struct {
		name   string
		prefix string
		origin uint32
		want   plugin.RPKIValidity
	}{
		{"exact match", "198.51.100.0/24", 64500, plugin.RPKIValid},
		{"covered by max length", "203.0.113.128/26", 64501, plugin.RPKIValid},
		{"wrong origin", "198.51.100.0/24", 64599, plugin.RPKIInvalid},
		{"longer than max length", "203.0.113.0/27", 64501, plugin.RPKINotFound},
		{"no covering payload", "192.0.2.0/24", 64500, plugin.RPKINotFound},
		{"ipv6 valid", "2001:db8:1::/48", 64502, plugin.RPKIValid},
		{"ipv6 wrong origin", "2001:db8:1::/48", 64999, plugin.RPKIInvalid},
		{"invalid prefix", "not-a-prefix", 1, plugin.RPKIUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var prefix netip.Prefix
			if tt.name != "invalid prefix" {
				prefix = p(t, tt.prefix)
			}
			if got := table.Validate(prefix, tt.origin); got != tt.want {
				t.Fatalf("Validate(%s, %d) = %q, want %q", tt.prefix, tt.origin, got, tt.want)
			}
		})
	}
	if table.Len() != 3 {
		t.Fatalf("Len = %d, want 3", table.Len())
	}
}

// A withdrawal removes exactly the payload it names.
func TestVRPsRemove(t *testing.T) {
	table := NewVRPs()
	table.Add(p(t, "198.51.100.0/24"), 24, 64500)
	table.Add(p(t, "198.51.100.0/24"), 25, 64500)
	table.Remove(p(t, "198.51.100.0/24"), 24, 64500)
	if table.Len() != 1 {
		t.Fatalf("Len = %d, want 1", table.Len())
	}
	if got := table.Validate(p(t, "198.51.100.0/24"), 64500); got != plugin.RPKIValid {
		t.Fatalf("remaining payload should still validate: %q", got)
	}
	table.Remove(p(t, "198.51.100.0/24"), 24, 64500)
	if table.Len() != 1 {
		t.Fatalf("removing an absent payload changed Len: %d", table.Len())
	}
	table.Remove(p(t, "198.51.100.0/24"), 25, 64500)
	if got := table.Validate(p(t, "198.51.100.0/24"), 64500); got != plugin.RPKINotFound {
		t.Fatalf("after both removals = %q, want notfound", got)
	}
}

// A replayed RTR announcement is stored once, so one Remove retires it.
func TestVRPsAddIdempotent(t *testing.T) {
	table := NewVRPs()
	table.Add(p(t, "198.51.100.0/24"), 24, 64500)
	table.Add(p(t, "198.51.100.0/24"), 24, 64500)
	if table.Len() != 1 {
		t.Fatalf("duplicate add stored %d payloads", table.Len())
	}
	table.Remove(p(t, "198.51.100.0/24"), 24, 64500)
	if got := table.Validate(p(t, "198.51.100.0/24"), 64500); got == plugin.RPKIValid {
		t.Fatalf("withdrawn payload still validates: %q", got)
	}
}

// An empty and nil table are unknown, never invalid.
func TestVRPsEmpty(t *testing.T) {
	if got := NewVRPs().Validate(p(t, "198.51.100.0/24"), 64500); got != plugin.RPKINotFound {
		t.Fatalf("empty table = %q, want notfound", got)
	}
	var nilTable *VRPs
	if got := nilTable.Validate(p(t, "198.51.100.0/24"), 64500); got != plugin.RPKIUnknown {
		t.Fatalf("nil table = %q, want unknown", got)
	}
}
