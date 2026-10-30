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
	table.Apply([]Change{{Prefix: p(t, "198.51.100.0/24"), MaxLen: 24, ASN: 64500}})
	table.Apply([]Change{{Prefix: p(t, "203.0.113.0/24"), MaxLen: 26, ASN: 64501}})
	table.Apply([]Change{{Prefix: p(t, "2001:db8::/32"), MaxLen: 48, ASN: 64502}})

	tests := []struct {
		name   string
		prefix string
		origin uint32
		want   plugin.RPKIValidity
	}{
		{"exact match", "198.51.100.0/24", 64500, plugin.RPKIValid},
		{"covered by max length", "203.0.113.128/26", 64501, plugin.RPKIValid},
		{"wrong origin", "198.51.100.0/24", 64599, plugin.RPKIInvalid},
		{"longer than max length", "203.0.113.0/27", 64501, plugin.RPKIInvalid},
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

// #158: RFC 6811 counts a payload as covering regardless of its max length,
// so a route longer than every matching max length (a more-specific hijack)
// is invalid, not not-found.
func TestVRPsValidateMaxLength(t *testing.T) {
	table := NewVRPs()
	table.Apply([]Change{
		{Prefix: p(t, "192.0.2.0/24"), MaxLen: 24, ASN: 64500},
		{Prefix: p(t, "2001:db8::/32"), MaxLen: 32, ASN: 64500},
		{Prefix: p(t, "198.51.100.0/24"), MaxLen: 24, ASN: 64501},
		{Prefix: p(t, "198.51.100.0/22"), MaxLen: 25, ASN: 64501},
	})

	tests := []struct {
		name   string
		prefix string
		origin uint32
		want   plugin.RPKIValidity
	}{
		{"ipv4 longer than max length", "192.0.2.0/25", 64500, plugin.RPKIInvalid},
		{"ipv4 at max length", "192.0.2.0/24", 64500, plugin.RPKIValid},
		{"ipv6 longer than max length", "2001:db8::/48", 64500, plugin.RPKIInvalid},
		{"ipv6 at max length", "2001:db8::/32", 64500, plugin.RPKIValid},
		{"another covering payload matches", "198.51.100.0/25", 64501, plugin.RPKIValid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := table.Validate(p(t, tt.prefix), tt.origin); got != tt.want {
				t.Fatalf("Validate(%s, %d) = %q, want %q", tt.prefix, tt.origin, got, tt.want)
			}
		})
	}
}

// A withdrawal removes exactly the payload it names, and a delta applies
// its records in order.
func TestVRPsApply(t *testing.T) {
	table := NewVRPs()
	table.Apply([]Change{{Prefix: p(t, "198.51.100.0/24"), MaxLen: 24, ASN: 64500}})
	table.Apply([]Change{{Prefix: p(t, "198.51.100.0/24"), MaxLen: 25, ASN: 64500}})
	table.Apply([]Change{{Prefix: p(t, "198.51.100.0/24"), MaxLen: 24, ASN: 64500, Withdraw: true}})
	if table.Len() != 1 {
		t.Fatalf("Len = %d, want 1", table.Len())
	}
	if got := table.Validate(p(t, "198.51.100.0/24"), 64500); got != plugin.RPKIValid {
		t.Fatalf("remaining payload should still validate: %q", got)
	}
	table.Apply([]Change{{Prefix: p(t, "198.51.100.0/24"), MaxLen: 24, ASN: 64500, Withdraw: true}})
	if table.Len() != 1 {
		t.Fatalf("removing an absent payload changed Len: %d", table.Len())
	}
	table.Apply([]Change{
		{Prefix: p(t, "203.0.113.0/24"), MaxLen: 24, ASN: 64501},
		{Prefix: p(t, "203.0.113.0/24"), MaxLen: 24, ASN: 64501, Withdraw: true},
		{Prefix: p(t, "198.51.100.0/24"), MaxLen: 25, ASN: 64500, Withdraw: true},
	})
	if table.Len() != 0 {
		t.Fatalf("announce then withdraw in one delta left Len %d", table.Len())
	}
	if got := table.Validate(p(t, "198.51.100.0/24"), 64500); got != plugin.RPKINotFound {
		t.Fatalf("after both removals = %q, want notfound", got)
	}
}

// A replayed RTR announcement is stored once, so one withdrawal retires it.
func TestVRPsAddIdempotent(t *testing.T) {
	table := NewVRPs()
	table.Apply([]Change{{Prefix: p(t, "198.51.100.0/24"), MaxLen: 24, ASN: 64500}})
	table.Apply([]Change{{Prefix: p(t, "198.51.100.0/24"), MaxLen: 24, ASN: 64500}})
	if table.Len() != 1 {
		t.Fatalf("duplicate add stored %d payloads", table.Len())
	}
	table.Apply([]Change{{Prefix: p(t, "198.51.100.0/24"), MaxLen: 24, ASN: 64500}, {Prefix: p(t, "198.51.100.0/24"), MaxLen: 24, ASN: 64500, Withdraw: true}})
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

// #289: Covering lists every payload whose prefix covers the query,
// shortest first, with its max length and origin.
func TestVRPsCovering(t *testing.T) {
	table := NewVRPs()
	table.Apply([]Change{
		{Prefix: p(t, "198.51.100.0/22"), MaxLen: 24, ASN: 64500},
		{Prefix: p(t, "198.51.100.0/24"), MaxLen: 24, ASN: 64501},
		{Prefix: p(t, "203.0.113.0/24"), MaxLen: 24, ASN: 64502},
	})
	got := table.Covering(p(t, "198.51.100.0/24"))
	want := []plugin.RPKIVRP{
		{Prefix: p(t, "198.51.100.0/22"), MaxLen: 24, ASN: 64500},
		{Prefix: p(t, "198.51.100.0/24"), MaxLen: 24, ASN: 64501},
	}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("Covering = %+v, want %+v", got, want)
	}
	if got := table.Covering(p(t, "192.0.2.0/24")); len(got) != 0 {
		t.Fatalf("uncovered = %+v", got)
	}
}
