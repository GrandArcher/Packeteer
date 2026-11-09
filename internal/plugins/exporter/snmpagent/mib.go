package snmpagent

import (
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// The status objects live under <enterprise>.2 and the provider table under
// <enterprise>.3. deploy/mib/PACKETEER-MIB.txt is the definition; a test
// checks every number here against it.
const (
	statusArc   = 2
	providerArc = 3
)

// Scalars under <enterprise>.2, each with instance .0.
const (
	objVersion = iota + 1
	objMode
	objReady
	objHARole
	objImprovements
	objRIBPrefixes
	objProbeRate
	objDataAge
)

// Columns of the provider table entry <enterprise>.3.1.<column>.<index>.
const (
	colName = iota + 2 // 1 is the not-accessible index
	colUp
	colLoss
	colRTT
	colJitter
	colTelemetryUp
	colInKbps
	colOutKbps
	colIn95Kbps
	colOut95Kbps
	colUsageKbps
	colCommitKbps
)

// HA roles, as in the MIB.
const (
	haStandalone = 1 + iota
	haActive
	haStandby
)

// value is one object instance.
type value struct {
	kind gosnmp.Asn1BER
	v    any
	// age marks the data-age scalar, which is computed per request from
	// the snapshot's time.
	age bool
}

// instance is one row of the MIB view: an OID and its value.
type instance struct {
	oid []uint32
	value
}

func gauge(n float64) value {
	switch {
	case math.IsNaN(n) || n < 0:
		n = 0
	case n > math.MaxUint32:
		n = math.MaxUint32
	}
	return value{kind: gosnmp.Gauge32, v: uint32(math.Round(n))}
}

func text(s string) value { return value{kind: gosnmp.OctetString, v: s} }

// truth is an SNMPv2-TC TruthValue: true(1), false(2).
func truth(b bool) value {
	if b {
		return value{kind: gosnmp.Integer, v: 1}
	}
	return value{kind: gosnmp.Integer, v: 2}
}

func integer(n int) value { return value{kind: gosnmp.Integer, v: n} }

// view is the sorted MIB at one snapshot.
type view struct {
	at   time.Time
	rows []instance
}

// series collects the samples of one metric by name.
type series map[string][]plugin.MetricSample

func (s series) one(name string) (float64, bool) {
	if v := s[name]; len(v) > 0 {
		return v[0].Value, true
	}
	return 0, false
}

// buildView turns a metrics snapshot into the MIB. An object whose metric is
// missing is left out instead of reported as zero: a walk then shows what
// Packeteer knows, and an NMS graph shows a gap, not a false zero.
// rate is the probe results per minute since the previous snapshot, when
// there is one.
func buildView(base []uint32, m plugin.MetricsRecord, rate *float64) *view {
	by := series{}
	for _, s := range m.Samples {
		by[s.Name] = append(by[s.Name], s)
	}
	var rows []instance
	add := func(arc uint32, tail []uint32, v value) {
		oid := append(slices.Clone(base), arc)
		rows = append(rows, instance{oid: append(oid, tail...), value: v})
	}
	scalar := func(obj uint32, v value) { add(statusArc, []uint32{obj, 0}, v) }

	if bi := by["packeteer_build_info"]; len(bi) > 0 {
		scalar(objVersion, text(bi[0].Labels["version"]))
		scalar(objMode, text(bi[0].Labels["mode"]))
	}
	if v, ok := by.one("packeteer_ready"); ok {
		scalar(objReady, truth(v == 1))
	}
	role := haStandalone
	if ha := by["packeteer_ha_active"]; len(ha) > 0 {
		role = haStandby
		if ha[0].Value == 1 {
			role = haActive
		}
	}
	scalar(objHARole, integer(role))
	if v, ok := by.one("packeteer_improvements_active"); ok {
		scalar(objImprovements, gauge(v))
	}
	if v, ok := by.one("packeteer_rib_prefixes"); ok {
		scalar(objRIBPrefixes, gauge(v))
	}
	if rate != nil {
		scalar(objProbeRate, gauge(*rate))
	}
	scalar(objDataAge, value{kind: gosnmp.Gauge32, age: true})

	// Providers are numbered by sorted name, so an index is stable until a
	// provider is added or removed.
	var names []string
	for _, s := range by["packeteer_provider_up"] {
		names = append(names, s.Labels["provider"])
	}
	sort.Strings(names)
	names = slices.Compact(names)
	for i, name := range names {
		idx := []uint32{uint32(i + 1)}
		col := func(c uint32, v value) { add(providerArc, append([]uint32{1, c}, idx...), v) }
		col(colName, text(name))
		for _, s := range by["packeteer_provider_up"] {
			if s.Labels["provider"] == name {
				col(colUp, truth(s.Value == 1))
				break
			}
		}
		if v, ok := mean(by["packeteer_probe_loss_ratio"], name); ok {
			col(colLoss, gauge(v*1000))
		}
		if v, ok := mean(by["packeteer_probe_rtt_seconds"], name); ok {
			col(colRTT, gauge(v*1e6))
		}
		if v, ok := mean(by["packeteer_probe_jitter_seconds"], name); ok {
			col(colJitter, gauge(v*1e6))
		}
		up, ok := first(by["packeteer_telemetry_up"], name)
		if !ok {
			continue
		}
		col(colTelemetryUp, truth(up == 1))
		if up == 1 {
			for _, c := range []struct {
				col    uint32
				metric string
			}{
				{colInKbps, "packeteer_telemetry_in_bps"}, {colOutKbps, "packeteer_telemetry_out_bps"},
				{colIn95Kbps, "packeteer_telemetry_in_95th_bps"}, {colOut95Kbps, "packeteer_telemetry_out_95th_bps"},
				{colUsageKbps, "packeteer_telemetry_usage_bps"},
			} {
				if v, ok := first(by[c.metric], name); ok {
					col(c.col, gauge(v/1000))
				}
			}
		}
		if v, ok := first(by["packeteer_telemetry_commit_bps"], name); ok && v > 0 {
			col(colCommitKbps, gauge(v/1000))
		}
	}
	sort.Slice(rows, func(i, j int) bool { return slices.Compare(rows[i].oid, rows[j].oid) < 0 })
	return &view{at: m.Time, rows: rows}
}

// mean averages the samples of one provider.
func mean(ss []plugin.MetricSample, provider string) (float64, bool) {
	var sum float64
	n := 0
	for _, s := range ss {
		if s.Labels["provider"] == provider {
			sum += s.Value
			n++
		}
	}
	if n == 0 {
		return 0, false
	}
	return sum / float64(n), true
}

// first is the reading of the provider's first series by interface name. A
// provider with several telemetry bindings reports the first.
func first(ss []plugin.MetricSample, provider string) (float64, bool) {
	best := -1
	for i, s := range ss {
		if s.Labels["provider"] == provider && (best < 0 || s.Labels["interface"] < ss[best].Labels["interface"]) {
			best = i
		}
	}
	if best < 0 {
		return 0, false
	}
	return ss[best].Value, true
}

// pdu renders a row for a response.
func (v *view) pdu(r instance, now time.Time) gosnmp.SnmpPDU {
	val := r.v
	if r.age {
		val = uint32(max(0, now.Sub(v.at)/time.Second))
	}
	return gosnmp.SnmpPDU{Name: oidString(r.oid), Type: r.kind, Value: val}
}

// get is the exact match for oid.
func (v *view) get(oid []uint32) (instance, bool) {
	i, found := slices.BinarySearchFunc(v.rows, oid, func(r instance, o []uint32) int { return slices.Compare(r.oid, o) })
	if !found {
		return instance{}, false
	}
	return v.rows[i], true
}

// next is the first row after oid.
func (v *view) next(oid []uint32) (instance, bool) {
	i, found := slices.BinarySearchFunc(v.rows, oid, func(r instance, o []uint32) int { return slices.Compare(r.oid, o) })
	if found {
		i++
	}
	if i >= len(v.rows) {
		return instance{}, false
	}
	return v.rows[i], true
}

func oidString(o []uint32) string {
	var b strings.Builder
	for _, n := range o {
		b.WriteByte('.')
		b.WriteString(strconv.FormatUint(uint64(n), 10))
	}
	return b.String()
}

// parseOID reads a dotted OID, with or without the leading dot.
func parseOID(s string) ([]uint32, bool) {
	s = strings.TrimPrefix(s, ".")
	if s == "" {
		return nil, false
	}
	parts := strings.Split(s, ".")
	oid := make([]uint32, len(parts))
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, false
		}
		oid[i] = uint32(n)
	}
	return oid, true
}
