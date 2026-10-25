// Package twamp is the TWAMP-Light test-session wire format (RFC 5357,
// unauthenticated mode) and a Session-Reflector. The twamp prober sends
// the Session-Sender packets; the packeteer-reflector command answers them.
// There is no control connection: TWAMP-Light (RFC 5357 appendix I)
// assumes the sender and the reflector agree on the port out of band.
package twamp

import (
	"encoding/binary"
	"errors"
	"time"
)

// Packet sizes in unauthenticated mode.
const (
	// SenderMinLen is the fixed part of a Session-Sender packet: sequence
	// number, timestamp, error estimate (RFC 5357 section 4.1.2).
	SenderMinLen = 14
	// ReflectorMinLen is the fixed part of a Session-Reflector packet
	// (RFC 5357 section 4.2.1).
	ReflectorMinLen = 41
	// MinSenderPadding is what a sender adds so the reflected packet,
	// whose fixed part is 27 octets longer, is the same size as the
	// sender's (RFC 5357 section 4.2.1).
	MinSenderPadding = ReflectorMinLen - SenderMinLen
	// DefaultPort is the TWAMP port (RFC 5357 section 3.1).
	DefaultPort = 862
	// UnsyncedErrorEstimate is an error estimate with S = 0 (clock not
	// synchronized), scale 0, and the smallest non-zero multiplier.
	UnsyncedErrorEstimate uint16 = 0x0001
	// UnknownTTL is the Sender TTL a reflector puts in its reply when it
	// cannot read the TTL of the received packet (RFC 5357 section 4.2.1).
	UnknownTTL uint8 = 255
)

// ErrShort is returned when a packet is shorter than its fixed part.
var ErrShort = errors.New("twamp: packet too short")

// SenderPacket is one Session-Sender test packet.
type SenderPacket struct {
	Seq           uint32
	Timestamp     time.Time
	ErrorEstimate uint16
	// Padding is the octets after the fixed part.
	Padding int
}

// Marshal encodes the packet. Padding octets are zero.
func (p SenderPacket) Marshal() []byte {
	b := make([]byte, SenderMinLen+max(p.Padding, 0))
	binary.BigEndian.PutUint32(b[0:4], p.Seq)
	putNTP(b[4:12], p.Timestamp)
	binary.BigEndian.PutUint16(b[12:14], p.ErrorEstimate)
	return b
}

// ParseSender decodes a Session-Sender packet.
func ParseSender(b []byte) (SenderPacket, error) {
	if len(b) < SenderMinLen {
		return SenderPacket{}, ErrShort
	}
	return SenderPacket{
		Seq:           binary.BigEndian.Uint32(b[0:4]),
		Timestamp:     ntpTime(b[4:12]),
		ErrorEstimate: binary.BigEndian.Uint16(b[12:14]),
		Padding:       len(b) - SenderMinLen,
	}, nil
}

// ReflectorPacket is one Session-Reflector test packet.
type ReflectorPacket struct {
	Seq                 uint32
	Timestamp           time.Time
	ErrorEstimate       uint16
	ReceiveTimestamp    time.Time
	SenderSeq           uint32
	SenderTimestamp     time.Time
	SenderErrorEstimate uint16
	SenderTTL           uint8
	Padding             int
}

// Marshal encodes the packet. The MBZ fields and the padding are zero.
func (p ReflectorPacket) Marshal() []byte {
	b := make([]byte, ReflectorMinLen+max(p.Padding, 0))
	binary.BigEndian.PutUint32(b[0:4], p.Seq)
	putNTP(b[4:12], p.Timestamp)
	binary.BigEndian.PutUint16(b[12:14], p.ErrorEstimate)
	putNTP(b[16:24], p.ReceiveTimestamp)
	binary.BigEndian.PutUint32(b[24:28], p.SenderSeq)
	putNTP(b[28:36], p.SenderTimestamp)
	binary.BigEndian.PutUint16(b[36:38], p.SenderErrorEstimate)
	b[40] = p.SenderTTL
	return b
}

// ParseReflector decodes a Session-Reflector packet.
func ParseReflector(b []byte) (ReflectorPacket, error) {
	if len(b) < ReflectorMinLen {
		return ReflectorPacket{}, ErrShort
	}
	return ReflectorPacket{
		Seq:                 binary.BigEndian.Uint32(b[0:4]),
		Timestamp:           ntpTime(b[4:12]),
		ErrorEstimate:       binary.BigEndian.Uint16(b[12:14]),
		ReceiveTimestamp:    ntpTime(b[16:24]),
		SenderSeq:           binary.BigEndian.Uint32(b[24:28]),
		SenderTimestamp:     ntpTime(b[28:36]),
		SenderErrorEstimate: binary.BigEndian.Uint16(b[36:38]),
		SenderTTL:           b[40],
		Padding:             len(b) - ReflectorMinLen,
	}, nil
}

// ntpEpochOffset is the seconds from the NTP epoch (1900) to the Unix
// epoch (1970).
const ntpEpochOffset = 2208988800

// putNTP writes t as a 64-bit NTP timestamp: 32 bits of seconds since
// 1900 and 32 bits of fraction (RFC 5905 section 6).
func putNTP(b []byte, t time.Time) {
	if t.IsZero() {
		clear(b[:8])
		return
	}
	sec := t.Unix() + ntpEpochOffset
	frac := uint64(t.Nanosecond()) << 32 / uint64(time.Second)
	binary.BigEndian.PutUint32(b[0:4], uint32(sec))
	binary.BigEndian.PutUint32(b[4:8], uint32(frac))
}

// ntpTime reads a 64-bit NTP timestamp. Seconds are taken in the NTP
// era that contains the Unix epoch, which holds until 2036.
func ntpTime(b []byte) time.Time {
	sec := binary.BigEndian.Uint32(b[0:4])
	frac := binary.BigEndian.Uint32(b[4:8])
	if sec == 0 && frac == 0 {
		return time.Time{}
	}
	ns := uint64(frac) * uint64(time.Second) >> 32
	return time.Unix(int64(sec)-ntpEpochOffset, int64(ns)).UTC()
}
