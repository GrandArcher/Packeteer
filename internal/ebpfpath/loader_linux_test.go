//go:build linux

package ebpfpath

import (
	"net/netip"
	"testing"
)

// Forget builds the key the kernel program wrote, so it must decode back
// to the same connection.
func TestEncodeTrackKeyRoundTrips(t *testing.T) {
	for _, k := range []TrackKey{
		{Local: netip.MustParseAddrPort("192.0.2.10:40000"), Remote: netip.MustParseAddrPort("198.51.100.7:443")},
		{Local: netip.MustParseAddrPort("[2001:db8:1::10]:51000"), Remote: netip.MustParseAddrPort("[2001:db8:ffff::20]:22")},
	} {
		got, err := DecodeTrackKey(encodeTrackKey(k))
		if err != nil || got != k {
			t.Errorf("key %+v came back as %+v, %v", k, got, err)
		}
	}
}
