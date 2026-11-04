package twamp

import (
	"testing"
	"time"
)

// FuzzParse feeds arbitrary datagrams to both packet parsers. The padding a
// parser reports is what lies after the fixed part, so nothing is read from
// outside the packet.
func FuzzParse(f *testing.F) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	f.Add(SenderPacket{Seq: 7, Timestamp: now, ErrorEstimate: 1, Padding: 27}.Marshal())
	f.Add(ReflectorPacket{Seq: 9, Timestamp: now, ReceiveTimestamp: now, SenderSeq: 7, SenderTimestamp: now, SenderTTL: 255}.Marshal())
	f.Add([]byte{0, 1, 2})
	f.Fuzz(func(t *testing.T, p []byte) {
		if s, err := ParseSender(p); err == nil && s.Padding != len(p)-SenderMinLen {
			t.Fatalf("sender padding %d from %d bytes", s.Padding, len(p))
		}
		if r, err := ParseReflector(p); err == nil && r.Padding != len(p)-ReflectorMinLen {
			t.Fatalf("reflector padding %d from %d bytes", r.Padding, len(p))
		}
	})
}
