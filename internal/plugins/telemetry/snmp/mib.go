package snmp

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// IF-MIB columns. 64-bit counters are preferred. 32-bit counters are the
// fallback when ifXTable is absent.
const (
	oidSysUpTime     = "1.3.6.1.2.1.1.3.0"
	oidIfDescr       = "1.3.6.1.2.1.2.2.1.2"
	oidIfSpeed       = "1.3.6.1.2.1.2.2.1.5"
	oidIfInOctets    = "1.3.6.1.2.1.2.2.1.10"
	oidIfOutOctets   = "1.3.6.1.2.1.2.2.1.16"
	oidIfName        = "1.3.6.1.2.1.31.1.1.1.1"
	oidIfHCInOctets  = "1.3.6.1.2.1.31.1.1.1.6"
	oidIfHCOutOctets = "1.3.6.1.2.1.31.1.1.1.10"
	oidIfHighSpeed   = "1.3.6.1.2.1.31.1.1.1.15"

	maxWalk    = 4096
	maxSaneBps = 100e12 // 100 Tbit/s. Above this the delta is not a rate.
)

func normOID(s string) string { return strings.TrimPrefix(s, ".") }

func joinOID(base string, index int) string {
	return normOID(base) + "." + strconv.Itoa(index)
}

func indexOf(column, full string) (int, bool) {
	rest := strings.TrimPrefix(normOID(full), normOID(column)+".")
	if rest == "" || rest == normOID(full) || strings.Contains(rest, ".") {
		return 0, false
	}
	n, err := strconv.Atoi(rest)
	if err != nil || strconv.Itoa(n) != rest || n <= 0 {
		return 0, false
	}
	return n, true
}

func counterOIDs(index, bits int) (inOID, outOID string) {
	if bits >= 64 {
		return joinOID(oidIfHCInOctets, index), joinOID(oidIfHCOutOctets, index)
	}
	return joinOID(oidIfInOctets, index), joinOID(oidIfOutOctets, index)
}

func missing(p gosnmp.SnmpPDU) bool {
	switch p.Type {
	case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView, gosnmp.Null:
		return true
	default:
		return false
	}
}

func pduString(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(strings.TrimRight(t, "\x00"))
	case []byte:
		return strings.TrimSpace(strings.TrimRight(string(t), "\x00"))
	default:
		return ""
	}
}

func pduUint(v any) (uint64, bool) {
	switch t := v.(type) {
	case uint64:
		return t, true
	case uint32:
		return uint64(t), true
	case uint:
		return uint64(t), true
	case int:
		if t < 0 {
			return 0, false
		}
		return uint64(t), true
	case int64:
		if t < 0 {
			return 0, false
		}
		return uint64(t), true
	case int32:
		if t < 0 {
			return 0, false
		}
		return uint64(t), true
	default:
		return 0, false
	}
}

func counterDelta(prev, cur uint64, bits int) uint64 {
	if bits <= 32 {
		return uint64(uint32(cur) - uint32(prev))
	}
	return cur - prev
}

func rateBps(delta uint64, dt time.Duration) float64 {
	if dt <= 0 {
		return math.Inf(1)
	}
	return float64(delta) * 8 / dt.Seconds()
}

// saneRate rejects a delta that cannot be a link rate. speedMbps 0 means
// the agent did not report a speed, so only the absolute cap applies.
// A known speed rejects anything above twice that speed, which is how a
// counter reset that is not a single wrap is dropped.
func saneRate(bps, speedMbps float64) bool {
	if math.IsNaN(bps) || math.IsInf(bps, 0) || bps < 0 || bps > maxSaneBps {
		return false
	}
	if speedMbps > 0 && bps > speedMbps*1e6*2 {
		return false
	}
	return true
}

func getMapped(sess session, oids []string) (map[string]gosnmp.SnmpPDU, error) {
	out := make(map[string]gosnmp.SnmpPDU, len(oids))
	const chunk = 16
	for i := 0; i < len(oids); i += chunk {
		j := i + chunk
		if j > len(oids) {
			j = len(oids)
		}
		vars, err := sess.Get(oids[i:j])
		if err != nil {
			return nil, err
		}
		for _, v := range vars {
			out[normOID(v.Name)] = v
		}
	}
	return out, nil
}

func findName(sess session, column, want string) (int, error) {
	pdus, err := sess.Walk(column)
	if err != nil {
		return 0, err
	}
	if len(pdus) > maxWalk {
		return 0, fmt.Errorf("interface walk returned %d rows", len(pdus))
	}
	found := 0
	idx := 0
	for _, p := range pdus {
		if missing(p) {
			continue
		}
		if pduString(p.Value) != want {
			continue
		}
		n, ok := indexOf(column, p.Name)
		if !ok {
			continue
		}
		found++
		idx = n
	}
	if found > 1 {
		return 0, fmt.Errorf("interface %q matches %d rows", want, found)
	}
	return idx, nil
}

// resolveIface maps an interface name or a decimal ifIndex to counters.
// bits is 64 when ifHCInOctets exists, otherwise 32.
func resolveIface(sess session, iface string) (idx int, speedMbps float64, bits int, err error) {
	if n, ok := ifIndex(iface); ok {
		return finishResolve(sess, n)
	}
	idx, nameErr := findName(sess, oidIfName, iface)
	if idx == 0 {
		var descrErr error
		idx, descrErr = findName(sess, oidIfDescr, iface)
		if idx == 0 {
			if nameErr != nil && descrErr != nil {
				return 0, 0, 0, fmt.Errorf("interface %q: ifName: %v; ifDescr: %v", iface, nameErr, descrErr)
			}
			if nameErr != nil && descrErr == nil {
				return 0, 0, 0, fmt.Errorf("interface %q not found (%v)", iface, nameErr)
			}
			if descrErr != nil {
				return 0, 0, 0, fmt.Errorf("interface %q not found (%v)", iface, descrErr)
			}
			return 0, 0, 0, fmt.Errorf("interface %q not found in ifName or ifDescr", iface)
		}
	}
	return finishResolve(sess, idx)
}

func finishResolve(sess session, idx int) (int, float64, int, error) {
	oids := []string{
		joinOID(oidIfHighSpeed, idx),
		joinOID(oidIfHCInOctets, idx),
		joinOID(oidIfSpeed, idx),
		joinOID(oidIfInOctets, idx),
	}
	pdus, err := getMapped(sess, oids)
	if err != nil {
		return 0, 0, 0, err
	}
	hc := pdus[joinOID(oidIfHCInOctets, idx)]
	in32 := pdus[joinOID(oidIfInOctets, idx)]
	bits := 32
	if _, ok := pdus[joinOID(oidIfHCInOctets, idx)]; ok && !missing(hc) {
		bits = 64
	} else if missing(in32) {
		return 0, 0, 0, fmt.Errorf("ifIndex %d has no octet counters", idx)
	}
	speed := 0.0
	if p, ok := pdus[joinOID(oidIfHighSpeed, idx)]; ok && !missing(p) {
		if n, ok := pduUint(p.Value); ok && n > 0 {
			speed = float64(n) // ifHighSpeed is megabits per second
		}
	}
	if speed == 0 {
		if p, ok := pdus[joinOID(oidIfSpeed, idx)]; ok && !missing(p) {
			if n, ok := pduUint(p.Value); ok && n > 0 {
				speed = float64(n) / 1e6
			}
		}
	}
	return idx, speed, bits, nil
}
