package flow

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

// Decoding lives here rather than in github.com/netsampler/goflow2. That
// module's go.mod requires a newer protobuf than the BGP speaker, plus
// collector dependencies the decoders themselves do not use. This reader
// keeps only the destination and octet fields target discovery needs.

const (
	maxTemplates   = 4096
	maxFlowSamples = 1024
	maxFlowRecords = 64

	ieInBytes            = 1
	ieDstV4              = 12
	ieOutBytes           = 23
	ieDstV6              = 28
	ieSamplingInterval   = 34
	ieSamplerRandom      = 50
	iePermanentBytes     = 85
	ieSamplingPacketRate = 305 // IPFIX samplingPacketInterval

	sflowEnterpriseShift = 12
	sflowFormatFlow      = 1
	sflowFormatExpanded  = 3
	sflowRawHeader       = 1
	sflowSampledIPv4     = 3
	sflowSampledIPv6     = 4
	sflowHeaderEthernet  = 1
	sflowHeaderIPv4      = 11
	sflowHeaderIPv6      = 12
)

var errNeedMore = errors.New("short record")

type observation struct {
	dst   netip.Addr
	bytes uint64
}

type fieldSpec struct {
	ie     uint16
	length uint16
	skip   bool // enterprise IE; consumed, not interpreted
}

type tmpl struct {
	fields []fieldSpec
}

type tmplKey struct {
	exp     netip.Addr
	version uint16
	domain  uint32
	id      uint16
}

type rateKey struct {
	exp     netip.Addr
	version uint16
	domain  uint32
}

// decoder holds NetFlow v9 / IPFIX templates and a sampling rate learned from
// options data. Templates are keyed by exporter, version, and observation
// domain. They are not flow records.
type decoder struct {
	mu    sync.Mutex
	tmpl  map[tmplKey]tmpl
	rates map[rateKey]uint64
}

func (d *decoder) decode(exporter netip.Addr, payload []byte) ([]observation, error) {
	if len(payload) < 2 {
		return nil, errors.New("short packet")
	}
	// sFlow's version is a uint32. NetFlow's is a uint16, so a v5 packet
	// never starts with 00 00 00 05.
	if len(payload) >= 4 && binary.BigEndian.Uint32(payload[:4]) == 5 {
		return decodeSFlow(payload)
	}
	switch binary.BigEndian.Uint16(payload[:2]) {
	case 5:
		return decodeV5(payload)
	case 9:
		return d.decodeV9(exporter, payload)
	case 10:
		return d.decodeIPFIX(exporter, payload)
	default:
		return nil, fmt.Errorf("unknown flow version %d", binary.BigEndian.Uint16(payload[:2]))
	}
}

func (d *decoder) init() {
	if d.tmpl == nil {
		d.tmpl = map[tmplKey]tmpl{}
		d.rates = map[rateKey]uint64{}
	}
}

func decodeV5(p []byte) ([]observation, error) {
	if len(p) < 24 {
		return nil, errors.New("netflow v5: short header")
	}
	count := int(binary.BigEndian.Uint16(p[2:4]))
	// Cisco packs a 2-bit sampling mode and a 14-bit interval into this
	// field. Zero means the octet counts are already absolute.
	rate := uint64(binary.BigEndian.Uint16(p[22:24]) & 0x3fff)
	rest := p[24:]
	var out []observation
	for i := 0; i < count; i++ {
		if len(rest) < 48 {
			return out, errors.New("netflow v5: short record")
		}
		rec := rest[:48]
		rest = rest[48:]
		octets := binary.BigEndian.Uint32(rec[20:24])
		if octets == 0 {
			continue
		}
		var dst4 [4]byte
		copy(dst4[:], rec[4:8])
		out = append(out, observation{dst: netip.AddrFrom4(dst4), bytes: scale(uint64(octets), rate)})
	}
	return out, nil
}

func (d *decoder) decodeV9(exporter netip.Addr, p []byte) ([]observation, error) {
	if len(p) < 20 {
		return nil, errors.New("netflow v9: short header")
	}
	domain := binary.BigEndian.Uint32(p[16:20])
	d.mu.Lock()
	defer d.mu.Unlock()
	d.init()
	return d.walkSets(exporter, 9, domain, p[20:])
}

func (d *decoder) decodeIPFIX(exporter netip.Addr, p []byte) ([]observation, error) {
	if len(p) < 16 {
		return nil, errors.New("ipfix: short header")
	}
	total := int(binary.BigEndian.Uint16(p[2:4]))
	if total < 16 || total > len(p) {
		return nil, errors.New("ipfix: bad length")
	}
	domain := binary.BigEndian.Uint32(p[12:16])
	d.mu.Lock()
	defer d.mu.Unlock()
	d.init()
	return d.walkSets(exporter, 10, domain, p[16:total])
}

func (d *decoder) walkSets(exp netip.Addr, version uint16, domain uint32, body []byte) ([]observation, error) {
	var obs []observation
	var errs []error
	for len(body) >= 4 {
		id := binary.BigEndian.Uint16(body[0:2])
		l := int(binary.BigEndian.Uint16(body[2:4]))
		if l < 4 || l > len(body) {
			errs = append(errs, errors.New("flowset length out of range"))
			break
		}
		set := body[4:l]
		body = body[l:]
		var err error
		switch {
		case version == 9 && id == 0:
			err = d.takeTemplates(exp, version, domain, set, false)
		case version == 9 && id == 1:
			err = d.takeV9Options(exp, domain, set)
		case version == 10 && id == 2:
			err = d.takeTemplates(exp, version, domain, set, true)
		case version == 10 && id == 3:
			err = d.takeIPFIXOptions(exp, domain, set)
		case id >= 256:
			var got []observation
			got, err = d.takeData(exp, version, domain, id, set)
			obs = append(obs, got...)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return obs, errors.Join(errs...)
}

func (d *decoder) takeTemplates(exp netip.Addr, version uint16, domain uint32, body []byte, ipfix bool) error {
	for len(body) >= 4 {
		id := binary.BigEndian.Uint16(body[0:2])
		n := int(binary.BigEndian.Uint16(body[2:4]))
		body = body[4:]
		if n == 0 {
			d.withdraw(exp, version, domain, id)
			continue
		}
		var fields []fieldSpec
		var err error
		if ipfix {
			fields, body, err = readIPFIXFields(body, n)
		} else {
			fields, body, err = readV9Fields(body, n)
		}
		if err != nil {
			return err
		}
		if err := d.store(tmplKey{exp, version, domain, id}, tmpl{fields: fields}); err != nil {
			return err
		}
	}
	return nil
}

func (d *decoder) takeV9Options(exp netip.Addr, domain uint32, body []byte) error {
	for len(body) >= 6 {
		id := binary.BigEndian.Uint16(body[0:2])
		scopeLen := int(binary.BigEndian.Uint16(body[2:4]))
		optLen := int(binary.BigEndian.Uint16(body[4:6]))
		body = body[6:]
		if scopeLen%4 != 0 || optLen%4 != 0 {
			return errors.New("netflow v9: options template length")
		}
		n := scopeLen/4 + optLen/4
		if n == 0 {
			d.withdraw(exp, 9, domain, id)
			continue
		}
		fields, rest, err := readV9Fields(body, n)
		if err != nil {
			return err
		}
		body = rest
		if err := d.store(tmplKey{exp, 9, domain, id}, tmpl{fields: fields}); err != nil {
			return err
		}
	}
	return nil
}

func (d *decoder) takeIPFIXOptions(exp netip.Addr, domain uint32, body []byte) error {
	for len(body) >= 6 {
		id := binary.BigEndian.Uint16(body[0:2])
		n := int(binary.BigEndian.Uint16(body[2:4]))
		scope := int(binary.BigEndian.Uint16(body[4:6]))
		body = body[6:]
		if n == 0 {
			d.withdraw(exp, 10, domain, id)
			continue
		}
		if scope > n {
			return errors.New("ipfix: scope count exceeds field count")
		}
		fields, rest, err := readIPFIXFields(body, n)
		if err != nil {
			return err
		}
		body = rest
		if err := d.store(tmplKey{exp, 10, domain, id}, tmpl{fields: fields}); err != nil {
			return err
		}
	}
	return nil
}

func readV9Fields(body []byte, n int) ([]fieldSpec, []byte, error) {
	need := n * 4
	if len(body) < need {
		return nil, body, errors.New("netflow v9: short template")
	}
	fields := make([]fieldSpec, n)
	for i := 0; i < n; i++ {
		off := i * 4
		fields[i] = fieldSpec{
			ie:     binary.BigEndian.Uint16(body[off:]),
			length: binary.BigEndian.Uint16(body[off+2:]),
		}
	}
	return fields, body[need:], nil
}

func readIPFIXFields(body []byte, n int) ([]fieldSpec, []byte, error) {
	fields := make([]fieldSpec, 0, n)
	for i := 0; i < n; i++ {
		if len(body) < 4 {
			return nil, body, errors.New("ipfix: short template")
		}
		ie := binary.BigEndian.Uint16(body[0:2])
		l := binary.BigEndian.Uint16(body[2:4])
		body = body[4:]
		f := fieldSpec{ie: ie, length: l}
		if ie&0x8000 != 0 {
			if len(body) < 4 {
				return nil, body, errors.New("ipfix: short enterprise field")
			}
			body = body[4:]
			f.ie = ie &^ 0x8000
			f.skip = true
		}
		fields = append(fields, f)
	}
	return fields, body, nil
}

func (d *decoder) store(k tmplKey, t tmpl) error {
	if !usable(t.fields) {
		return nil
	}
	if _, ok := d.tmpl[k]; !ok && len(d.tmpl) >= maxTemplates {
		return errors.New("template table full")
	}
	d.tmpl[k] = t
	return nil
}

func usable(fields []fieldSpec) bool {
	n := 0
	for _, f := range fields {
		if f.length == 0xffff {
			n++
		} else {
			n += int(f.length)
		}
	}
	return n > 0
}

// withdraw removes one template. An id below 256 withdraws every template for
// that exporter and domain (IPFIX uses template id 2 or 3 for this; v9 uses 0).
func (d *decoder) withdraw(exp netip.Addr, version uint16, domain uint32, id uint16) {
	if id < 256 {
		for k := range d.tmpl {
			if k.exp == exp && k.version == version && k.domain == domain {
				delete(d.tmpl, k)
			}
		}
		return
	}
	delete(d.tmpl, tmplKey{exp, version, domain, id})
}

type gotRec struct {
	dst     netip.Addr
	inB     uint64
	outB    uint64
	haveIn  bool
	haveOut bool
	rate    uint64
}

func (d *decoder) takeData(exp netip.Addr, version uint16, domain uint32, id uint16, body []byte) ([]observation, error) {
	t, ok := d.tmpl[tmplKey{exp, version, domain, id}]
	if !ok {
		return nil, fmt.Errorf("template %d not found", id)
	}
	rk := rateKey{exp, version, domain}
	var obs []observation
	for len(body) > 0 {
		rec, rest, err := nextRecord(body, t.fields)
		if errors.Is(err, errNeedMore) {
			break
		}
		if err != nil {
			return obs, err
		}
		if len(rest) >= len(body) {
			break
		}
		body = rest
		if rec.rate > 0 {
			d.rates[rk] = rec.rate
		}
		octets, keep := octetsOf(rec)
		if !keep {
			continue
		}
		rate := rec.rate
		if rate == 0 {
			rate = d.rates[rk]
		}
		obs = append(obs, observation{dst: rec.dst, bytes: scale(octets, rate)})
	}
	return obs, nil
}

func octetsOf(rec gotRec) (uint64, bool) {
	if rec.haveIn && rec.inB > 0 {
		return rec.inB, rec.dst.IsValid()
	}
	if rec.haveOut && rec.outB > 0 {
		return rec.outB, rec.dst.IsValid()
	}
	return 0, false
}

func nextRecord(body []byte, fields []fieldSpec) (gotRec, []byte, error) {
	min := 0
	for _, f := range fields {
		if f.length == 0xffff {
			min++
		} else {
			min += int(f.length)
		}
	}
	if min == 0 || len(body) < min {
		return gotRec{}, body, errNeedMore
	}
	var rec gotRec
	for _, f := range fields {
		val, rest, ok := takeField(body, f.length)
		if !ok {
			return gotRec{}, body, errors.New("truncated flow record")
		}
		body = rest
		if f.skip {
			continue
		}
		switch f.ie {
		case ieDstV4:
			if len(val) == 4 {
				var a [4]byte
				copy(a[:], val)
				rec.dst = netip.AddrFrom4(a)
			}
		case ieDstV6:
			if len(val) == 16 {
				var a [16]byte
				copy(a[:], val)
				rec.dst = netip.AddrFrom16(a)
			}
		case ieInBytes, iePermanentBytes:
			if n, ok := u64be(val); ok {
				rec.inB = n
				rec.haveIn = true
			}
		case ieOutBytes:
			if n, ok := u64be(val); ok {
				rec.outB = n
				rec.haveOut = true
			}
		case ieSamplingInterval, ieSamplerRandom, ieSamplingPacketRate:
			if n, ok := u64be(val); ok && n > 0 {
				rec.rate = n
			}
		}
	}
	return rec, body, nil
}

func takeField(body []byte, length uint16) ([]byte, []byte, bool) {
	if length == 0xffff {
		if len(body) < 1 {
			return nil, body, false
		}
		n := int(body[0])
		body = body[1:]
		if n == 255 {
			if len(body) < 2 {
				return nil, body, false
			}
			n = int(binary.BigEndian.Uint16(body[:2]))
			body = body[2:]
		}
		length = uint16(n)
	}
	if int(length) > len(body) {
		return nil, body, false
	}
	return body[:length], body[length:], true
}

func u64be(b []byte) (uint64, bool) {
	if len(b) == 0 || len(b) > 8 {
		return 0, false
	}
	var n uint64
	for _, c := range b {
		n = n<<8 | uint64(c)
	}
	return n, true
}

func scale(octets, rate uint64) uint64 {
	if rate <= 1 || octets == 0 {
		return octets
	}
	if octets > ^uint64(0)/rate {
		return ^uint64(0)
	}
	return octets * rate
}

func decodeSFlow(p []byte) ([]observation, error) {
	if len(p) < 28 {
		return nil, errors.New("sflow: short header")
	}
	if binary.BigEndian.Uint32(p[:4]) != 5 {
		return nil, errors.New("sflow: bad version")
	}
	af := binary.BigEndian.Uint32(p[4:8])
	off := 8
	switch af {
	case 1:
		off += 4
	case 2:
		off += 16
	default:
		return nil, fmt.Errorf("sflow: address type %d", af)
	}
	// sub-agent, sequence, uptime, sample count
	if len(p) < off+16 {
		return nil, errors.New("sflow: short header")
	}
	n := binary.BigEndian.Uint32(p[off+12 : off+16])
	off += 16
	if n > maxFlowSamples {
		return nil, errors.New("sflow: too many samples")
	}
	var out []observation
	for i := uint32(0); i < n; i++ {
		if len(p)-off < 8 {
			return out, errors.New("sflow: short sample")
		}
		format := binary.BigEndian.Uint32(p[off:])
		l := int(binary.BigEndian.Uint32(p[off+4:]))
		off += 8
		if l < 0 || l > len(p)-off {
			return out, errors.New("sflow: sample overruns packet")
		}
		body := p[off : off+l]
		off += l
		if format>>sflowEnterpriseShift != 0 {
			continue
		}
		var o observation
		var ok bool
		switch format & 0xfff {
		case sflowFormatFlow:
			o, ok = flowSample(body, false)
		case sflowFormatExpanded:
			o, ok = flowSample(body, true)
		}
		if ok {
			out = append(out, o)
		}
	}
	return out, nil
}

func flowSample(body []byte, expanded bool) (observation, bool) {
	need := 8 + 8 + 8 + 4 // seq+source, rate+pool, drops+input/output header, nrecords
	if expanded {
		need = 12 + 8 + 16 + 4 // seq+source type/index, rate+pool, ifs, nrecords
	}
	if len(body) < need {
		return observation{}, false
	}
	off := 0
	if expanded {
		off = 12
	} else {
		off = 8
	}
	rate := binary.BigEndian.Uint32(body[off:])
	off += 8 // rate + pool
	off += 4 // drops
	if expanded {
		off += 16
	} else {
		off += 8
	}
	if len(body) < off+4 {
		return observation{}, false
	}
	n := binary.BigEndian.Uint32(body[off:])
	off += 4
	if n > maxFlowRecords {
		return observation{}, false
	}
	var header, explicit observation
	var headerOK, explicitOK bool
	for i := uint32(0); i < n && len(body)-off >= 8; i++ {
		format := binary.BigEndian.Uint32(body[off:])
		l := int(binary.BigEndian.Uint32(body[off+4:]))
		off += 8
		if l > len(body)-off {
			return observation{}, false
		}
		rec := body[off : off+l]
		off += l
		if format>>sflowEnterpriseShift != 0 {
			continue
		}
		switch format & 0xfff {
		case sflowRawHeader:
			if !headerOK {
				if o, ok := sampledHeader(rec); ok {
					header, headerOK = o, true
				}
			}
		case sflowSampledIPv4:
			if o, ok := sampledIPv4(rec); ok {
				explicit, explicitOK = o, true
			}
		case sflowSampledIPv6:
			if o, ok := sampledIPv6(rec); ok {
				explicit, explicitOK = o, true
			}
		}
	}
	o := header
	ok := headerOK
	if explicitOK {
		o, ok = explicit, true
	}
	if !ok || o.bytes == 0 || !o.dst.IsValid() {
		return observation{}, false
	}
	r := uint64(rate)
	if r == 0 {
		r = 1
	}
	o.bytes = scale(o.bytes, r)
	return o, true
}

func sampledIPv4(rec []byte) (observation, bool) {
	// length, protocol, src, dst, srcPort, dstPort, flags, tos: 32 bytes
	if len(rec) < 32 {
		return observation{}, false
	}
	n := binary.BigEndian.Uint32(rec[0:4])
	var dst [4]byte
	copy(dst[:], rec[12:16])
	if n == 0 {
		return observation{}, false
	}
	return observation{dst: netip.AddrFrom4(dst), bytes: uint64(n)}, true
}

func sampledIPv6(rec []byte) (observation, bool) {
	// length, protocol, src16, dst16, ports, flags, priority: 56 bytes
	if len(rec) < 56 {
		return observation{}, false
	}
	n := binary.BigEndian.Uint32(rec[0:4])
	var dst [16]byte
	copy(dst[:], rec[24:40])
	if n == 0 {
		return observation{}, false
	}
	return observation{dst: netip.AddrFrom16(dst), bytes: uint64(n)}, true
}

func sampledHeader(rec []byte) (observation, bool) {
	if len(rec) < 16 {
		return observation{}, false
	}
	proto := binary.BigEndian.Uint32(rec[0:4])
	frameLen := binary.BigEndian.Uint32(rec[4:8])
	hdrLen := int(binary.BigEndian.Uint32(rec[12:16]))
	if hdrLen < 0 || hdrLen > len(rec)-16 {
		return observation{}, false
	}
	hdr := rec[16 : 16+hdrLen]
	var dst netip.Addr
	var n uint32
	var ok bool
	switch proto {
	case sflowHeaderEthernet:
		dst, n, ok = parseEthernet(hdr, frameLen)
	case sflowHeaderIPv4:
		dst, n, ok = parseIPv4(hdr, frameLen)
	case sflowHeaderIPv6:
		dst, n, ok = parseIPv6(hdr, frameLen)
	default:
		return observation{}, false
	}
	if !ok || n == 0 {
		return observation{}, false
	}
	return observation{dst: dst, bytes: uint64(n)}, true
}

func parseEthernet(hdr []byte, frameLen uint32) (netip.Addr, uint32, bool) {
	if len(hdr) < 14 {
		return netip.Addr{}, 0, false
	}
	off := 12
	et := binary.BigEndian.Uint16(hdr[off : off+2])
	off += 2
	for et == 0x8100 || et == 0x88a8 || et == 0x9100 {
		if len(hdr) < off+4 {
			return netip.Addr{}, 0, false
		}
		et = binary.BigEndian.Uint16(hdr[off+2 : off+4])
		off += 4
	}
	switch et {
	case 0x0800:
		return parseIPv4(hdr[off:], frameLen)
	case 0x86dd:
		return parseIPv6(hdr[off:], frameLen)
	default:
		return netip.Addr{}, 0, false
	}
}

func parseIPv4(b []byte, frameLen uint32) (netip.Addr, uint32, bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return netip.Addr{}, 0, false
	}
	var dst [4]byte
	copy(dst[:], b[16:20])
	n := uint32(binary.BigEndian.Uint16(b[2:4]))
	if n < 20 {
		n = frameLen
	}
	if n == 0 {
		return netip.Addr{}, 0, false
	}
	return netip.AddrFrom4(dst), n, true
}

func parseIPv6(b []byte, frameLen uint32) (netip.Addr, uint32, bool) {
	if len(b) < 40 || b[0]>>4 != 6 {
		return netip.Addr{}, 0, false
	}
	var dst [16]byte
	copy(dst[:], b[24:40])
	payload := uint32(binary.BigEndian.Uint16(b[4:6]))
	n := payload + 40
	if payload == 0 {
		n = frameLen
	}
	if n == 0 {
		return netip.Addr{}, 0, false
	}
	return netip.AddrFrom16(dst), n, true
}
