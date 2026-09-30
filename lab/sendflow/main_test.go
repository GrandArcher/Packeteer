package main

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestParseAndExport(t *testing.T) {
	flows, err := parse("# baseline\n198.51.100.10 udp 8\n\n203.0.113.10 6 0.5\n")
	if err != nil || len(flows) != 2 || flows[0].proto != 17 || flows[1].proto != 6 || flows[1].mbps != 0.5 {
		t.Fatalf("parse = %+v, %v", flows, err)
	}
	for _, bad := range []string{"198.51.100.10 udp", "nope udp 1", "2001:db8::1 udp 1", "198.51.100.10 bogus 1", "198.51.100.10 udp -1"} {
		if _, err := parse(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	b := export(flows, 200*time.Millisecond, 7, time.Unix(1_700_000_000, 0))
	if len(b) != 24+2*48 || binary.BigEndian.Uint16(b[0:]) != 5 || binary.BigEndian.Uint16(b[2:]) != 2 || binary.BigEndian.Uint32(b[16:]) != 7 {
		t.Fatalf("header = %x", b[:24])
	}
	// 8 Mbit/s for 200ms is 200000 bytes, toward 198.51.100.10 over udp.
	if got := binary.BigEndian.Uint32(b[24+20:]); got != 200000 || b[24+38] != 17 || b[24+4] != 198 || b[24+7] != 10 {
		t.Fatalf("record 0: octets %d proto %d dst %v", got, b[24+38], b[24+4:24+8])
	}
}
