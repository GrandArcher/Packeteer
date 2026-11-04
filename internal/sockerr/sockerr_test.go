//go:build linux

package sockerr

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

func TestParseDataV4(t *testing.T) {
	data := make([]byte, 16+16)
	binary.LittleEndian.PutUint32(data[0:4], uint32(unix.ECONNREFUSED))
	data[4] = unix.SO_EE_ORIGIN_ICMP
	data[5] = 11
	binary.LittleEndian.PutUint16(data[16:18], unix.AF_INET)
	copy(data[20:24], []byte{203, 0, 113, 1})
	from, typ, ok := ParseData(data)
	if !ok || typ != 11 || from.String() != "203.0.113.1" {
		t.Fatalf("from=%s typ=%d ok=%v", from, typ, ok)
	}
}

func TestParseDataV6(t *testing.T) {
	data := make([]byte, 16+28)
	data[4] = unix.SO_EE_ORIGIN_ICMP6
	data[5] = 3
	binary.LittleEndian.PutUint16(data[16:18], unix.AF_INET6)
	copy(data[24:40], []byte{0x20, 0x01, 0x0d, 0xb8, 15: 1})
	from, typ, ok := ParseData(data)
	if !ok || typ != 3 || from.String() != "2001:db8::1" {
		t.Fatalf("from=%s typ=%d ok=%v", from, typ, ok)
	}
}

func TestParseDataRejects(t *testing.T) {
	good := make([]byte, 16+16)
	good[4] = unix.SO_EE_ORIGIN_ICMP
	binary.LittleEndian.PutUint16(good[16:18], unix.AF_INET)
	if _, _, ok := ParseData(good); !ok {
		t.Fatal("baseline message rejected")
	}
	local := append([]byte(nil), good...)
	local[4] = unix.SO_EE_ORIGIN_LOCAL
	short := good[:16+4]
	badFamily := append([]byte(nil), good...)
	binary.LittleEndian.PutUint16(badFamily[16:18], unix.AF_UNIX)
	for name, d := range map[string][]byte{"local origin": local, "short": short, "unknown family": badFamily, "empty": nil} {
		if _, _, ok := ParseData(d); ok {
			t.Errorf("%s accepted", name)
		}
	}
	if _, _, ok := Parse([]byte{1, 2, 3}); ok {
		t.Error("garbage control message accepted")
	}
}
