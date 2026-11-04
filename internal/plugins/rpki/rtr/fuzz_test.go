package rtr

import (
	"bytes"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/rpki"
)

// FuzzRTRStream splits arbitrary bytes into PDUs and feeds them to a client
// the way a session does, from both a Reset and a Serial response. A cache
// server is untrusted input: it may end the session with an error, never
// panic or grow the cache past the VRP bound.
func FuzzRTRStream(f *testing.F) {
	f.Add(bytes.Join([][]byte{
		cacheResponsePDU(),
		ipv4PDU(f, "198.51.100.0/24", 24, 64500, true),
		ipv6PDU(f, "2001:db8:100::/48", 56, 64501, true),
		routerKeyPDU(),
		endOfDataPDU(3),
	}, nil))
	f.Add(bytes.Join([][]byte{cacheResponsePDU(), ipv4PDU(f, "203.0.113.0/24", 24, 64502, false), endOfDataPDU(4)}, nil))
	f.Add(bytes.Join([][]byte{serialNotifyPDU(7, 99), errorReportPDU(2)}, nil))
	f.Add([]byte{protocolVersion, pduIPv4Prefix, 0, 0, 0, 0, 0, 20, 1, 24, 33, 0, 192, 0, 2, 0, 0, 0, 0xfb, 0xf0})
	f.Fuzz(func(t *testing.T, p []byte) {
		for _, serial := range []bool{false, true} {
			c := &Client{cfg: Config{Timing: rpki.Timing{Staleness: time.Hour}}, cache: rpki.NewVRPs()}
			resp, _ := resetRequest()
			if serial {
				resp, _ = c.request()
			}
			pdus, _, err := splitPDUs(p)
			if err != nil {
				continue
			}
			for _, pdu := range pdus {
				if resp, _, err = c.handle(pdu, resp); err != nil {
					break
				}
			}
			if c.liveCache().Len() > rpki.MaxVRPs {
				t.Fatalf("cache holds %d payloads", c.liveCache().Len())
			}
		}
	})
}
