package snmpagent

import (
	"testing"

	"github.com/gosnmp/gosnmp"
)

// FuzzBER feeds arbitrary datagrams to the BER reader that runs on
// unauthenticated input before anything is decoded. An element must lie
// inside the bytes it was read from, and the header read must not panic.
func FuzzBER(f *testing.F) {
	f.Add(v3Message(f, "engine-0123456789", "noc"))
	v2 := &gosnmp.SnmpPacket{Version: gosnmp.Version2c, Community: "public", PDUType: gosnmp.GetRequest, RequestID: 1,
		Variables: []gosnmp.SnmpPDU{{Name: "1.3.6.1.2.1.1.1.0", Type: gosnmp.Null}}}
	if raw, err := v2.MarshalMsg(); err == nil {
		f.Add(raw)
	}
	f.Add([]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0x30, 0x80})
	f.Add([]byte{0x30, 0x03, 0x02, 0x01})
	f.Fuzz(func(t *testing.T, p []byte) {
		_, content, rest, ok := tlv(p)
		if ok && len(content)+len(rest) > len(p) {
			t.Fatalf("element of %d bytes and %d after it from %d", len(content), len(rest), len(p))
		}
		if _, engine, ok := msgHeader(p); ok && len(engine) > len(p) {
			t.Fatalf("engine id of %d bytes from %d", len(engine), len(p))
		}
	})
}
