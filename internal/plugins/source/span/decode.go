package span

import (
	"encoding/binary"
	"net/netip"
)

// Link types, as numbered in pcap files (LINKTYPE_*).
const (
	linkEthernet = 1
	linkRaw      = 101
	linkLinuxSLL = 113
	linkIPv4     = 228
	linkIPv6     = 229
)

const (
	etherIPv4  = 0x0800
	etherIPv6  = 0x86dd
	etherVLAN  = 0x8100
	etherQinQ  = 0x88a8
	etherQinQ2 = 0x9100
	protoTCP   = 6

	maxVLANTags = 2
	maxIPv6Ext  = 8
)

// TCP flag bits.
const (
	flagFIN = 0x01
	flagSYN = 0x02
	flagRST = 0x04
	flagACK = 0x10
)

// segment is the part of one TCP packet the tracker needs. Payload is the
// TCP payload length from the IP header, so a truncated capture still
// counts the bytes the sender put on the wire.
type segment struct {
	src, dst     netip.Addr
	sport, dport uint16
	seq          uint32
	flags        uint8
	payload      uint32
}

// decodeFrame parses one captured frame. ok is false for anything that is
// not a TCP segment over IPv4 or IPv6, and for truncated headers.
func decodeFrame(link int, b []byte) (segment, bool) {
	switch link {
	case linkEthernet:
		if len(b) < 14 {
			return segment{}, false
		}
		et := binary.BigEndian.Uint16(b[12:14])
		b = b[14:]
		for i := 0; i < maxVLANTags && (et == etherVLAN || et == etherQinQ || et == etherQinQ2); i++ {
			if len(b) < 4 {
				return segment{}, false
			}
			et = binary.BigEndian.Uint16(b[2:4])
			b = b[4:]
		}
		return decodeEther(et, b)
	case linkLinuxSLL:
		if len(b) < 16 {
			return segment{}, false
		}
		return decodeEther(binary.BigEndian.Uint16(b[14:16]), b[16:])
	case linkRaw, linkIPv4, linkIPv6:
		if len(b) < 1 {
			return segment{}, false
		}
		switch b[0] >> 4 {
		case 4:
			return decodeIPv4(b)
		case 6:
			return decodeIPv6(b)
		}
	}
	return segment{}, false
}

func decodeEther(et uint16, b []byte) (segment, bool) {
	switch et {
	case etherIPv4:
		return decodeIPv4(b)
	case etherIPv6:
		return decodeIPv6(b)
	}
	return segment{}, false
}

func decodeIPv4(b []byte) (segment, bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return segment{}, false
	}
	ihl := int(b[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if ihl < 20 || len(b) < ihl || total < ihl || b[9] != protoTCP {
		return segment{}, false
	}
	// A non-first fragment has no TCP header.
	if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
		return segment{}, false
	}
	var s, d [4]byte
	copy(s[:], b[12:16])
	copy(d[:], b[16:20])
	return decodeTCP(netip.AddrFrom4(s), netip.AddrFrom4(d), b[ihl:], total-ihl)
}

func decodeIPv6(b []byte) (segment, bool) {
	if len(b) < 40 || b[0]>>4 != 6 {
		return segment{}, false
	}
	plen := int(binary.BigEndian.Uint16(b[4:6]))
	next := b[6]
	var s, d [16]byte
	copy(s[:], b[8:24])
	copy(d[:], b[24:40])
	rest := b[40:]
	for i := 0; i < maxIPv6Ext && next != protoTCP; i++ {
		switch next {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if len(rest) < 8 {
				return segment{}, false
			}
			n := (int(rest[1]) + 1) * 8
			if len(rest) < n || plen < n {
				return segment{}, false
			}
			next = rest[0]
			rest = rest[n:]
			plen -= n
		case 44: // fragment: only the first fragment carries TCP
			if len(rest) < 8 || binary.BigEndian.Uint16(rest[2:4])&0xfff8 != 0 {
				return segment{}, false
			}
			next = rest[0]
			rest = rest[8:]
			plen -= 8
		default:
			return segment{}, false
		}
	}
	if next != protoTCP {
		return segment{}, false
	}
	return decodeTCP(netip.AddrFrom16(s), netip.AddrFrom16(d), rest, plen)
}

// decodeTCP reads the TCP header. l4len is the TCP length from the IP header.
func decodeTCP(src, dst netip.Addr, b []byte, l4len int) (segment, bool) {
	if len(b) < 20 {
		return segment{}, false
	}
	off := int(b[12]>>4) * 4
	if off < 20 || l4len < off {
		return segment{}, false
	}
	return segment{
		src:     src,
		dst:     dst,
		sport:   binary.BigEndian.Uint16(b[0:2]),
		dport:   binary.BigEndian.Uint16(b[2:4]),
		seq:     binary.BigEndian.Uint32(b[4:8]),
		flags:   b[13],
		payload: uint32(l4len - off),
	}, true
}
