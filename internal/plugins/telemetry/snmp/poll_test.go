package snmp

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type fakeSession struct {
	get  func([]string) ([]gosnmp.SnmpPDU, error)
	walk func(string) ([]gosnmp.SnmpPDU, error)
}

func (f *fakeSession) Get(oids []string) ([]gosnmp.SnmpPDU, error) { return f.get(oids) }
func (f *fakeSession) Walk(oid string) ([]gosnmp.SnmpPDU, error) {
	if f.walk == nil {
		return nil, nil
	}
	return f.walk(oid)
}
func (f *fakeSession) Close() error { return nil }

func pduCounter(oid string, v uint64, bits int) gosnmp.SnmpPDU {
	typ := gosnmp.Counter64
	var val any = v
	if bits == 32 {
		typ = gosnmp.Counter32
		val = uint32(v)
	}
	return gosnmp.SnmpPDU{Name: "." + oid, Type: typ, Value: val}
}

func TestPollRates95thAndReset(t *testing.T) {
	c := mustNew(t, baseYAML, map[string]string{"PACKETEER_SNMP_COMMUNITY": "lab-community-value"})
	var inC, outC uint64 = 1000, 1000
	var ticks uint32 = 10_000
	c.dial = func(context.Context, hostSpec) (session, error) {
		return &fakeSession{
			walk: func(oid string) ([]gosnmp.SnmpPDU, error) {
				if normOID(oid) != oidIfName {
					return nil, nil
				}
				return []gosnmp.SnmpPDU{{Name: "." + joinOID(oidIfName, 5), Type: gosnmp.OctetString, Value: "ether1"}}, nil
			},
			get: func(oids []string) ([]gosnmp.SnmpPDU, error) {
				var out []gosnmp.SnmpPDU
				for _, oid := range oids {
					switch normOID(oid) {
					case joinOID(oidIfHighSpeed, 5):
						out = append(out, gosnmp.SnmpPDU{Name: "." + oid, Type: gosnmp.Gauge32, Value: uint(1000)})
					case joinOID(oidIfHCInOctets, 5):
						out = append(out, pduCounter(normOID(oid), inC, 64))
					case joinOID(oidIfHCOutOctets, 5):
						out = append(out, pduCounter(normOID(oid), outC, 64))
					case oidSysUpTime:
						out = append(out, gosnmp.SnmpPDU{Name: "." + oid, Type: gosnmp.TimeTicks, Value: ticks})
					default:
						out = append(out, gosnmp.SnmpPDU{Name: "." + oid, Type: gosnmp.NoSuchInstance})
					}
				}
				return out, nil
			},
		}, nil
	}

	t0 := time.Now().UTC()
	c.poll(context.Background(), t0)
	rows, _ := c.Snapshot(context.Background())
	if rows[0].Samples != 0 || rows[0].Error != "" || rows[0].IfIndex != 5 {
		t.Fatalf("baseline = %+v", rows[0])
	}

	// 7_500_000 octets over 60s is 1 Mbps in. Out is twice that.
	inC += 7_500_000
	outC += 15_000_000
	ticks += 6000
	c.poll(context.Background(), t0.Add(time.Minute))
	rows, _ = c.Snapshot(context.Background())
	if rows[0].Samples != 1 || math.Abs(rows[0].InMbps-1) > 0.01 || math.Abs(rows[0].OutMbps-2) > 0.01 {
		t.Fatalf("rate = %+v", rows[0])
	}
	if !rows[0].Single || math.Abs(rows[0].UsageMbps-2) > 0.01 || rows[0].Mode != plugin.PercentileGreaterSeparate {
		t.Fatalf("95th = %+v", rows[0])
	}

	// sysUpTime went backwards: no new sample, baseline moves.
	ticks = 100
	inC += 7_500_000 * 100
	c.poll(context.Background(), t0.Add(2*time.Minute))
	rows, _ = c.Snapshot(context.Background())
	if rows[0].Samples != 1 || rows[0].Error == "" {
		t.Fatalf("reboot = %+v", rows[0])
	}

	// The minute after the reset has no counter change, so it is a real
	// 0 Mbit/s sample, not another baseline. The minute after that is 1 Mbit/s.
	ticks = 200
	c.poll(context.Background(), t0.Add(3*time.Minute))
	inC += 7_500_000
	outC += 7_500_000
	ticks = 800
	c.poll(context.Background(), t0.Add(4*time.Minute))
	rows, _ = c.Snapshot(context.Background())
	if rows[0].Samples != 3 || rows[0].Error != "" || math.Abs(rows[0].InMbps-1) > 0.01 || math.Abs(rows[0].UsageMbps-2) > 0.01 {
		t.Fatalf("after reset = %+v", rows[0])
	}
}

func TestPollGapAndAmbiguousName(t *testing.T) {
	c := mustNew(t, baseYAML, map[string]string{"PACKETEER_SNMP_COMMUNITY": "lab-community-value"})
	var inC uint64 = 1000
	c.dial = func(context.Context, hostSpec) (session, error) {
		return &fakeSession{
			walk: func(string) ([]gosnmp.SnmpPDU, error) {
				return []gosnmp.SnmpPDU{
					{Name: "." + joinOID(oidIfName, 1), Type: gosnmp.OctetString, Value: "ether1"},
					{Name: "." + joinOID(oidIfName, 2), Type: gosnmp.OctetString, Value: "ether1"},
				}, nil
			},
			get: func(oids []string) ([]gosnmp.SnmpPDU, error) {
				return nil, nil
			},
		}, nil
	}
	t0 := time.Now().UTC()
	c.poll(context.Background(), t0)
	rows, _ := c.Snapshot(context.Background())
	if rows[0].Error == "" || rows[0].Samples != 0 {
		t.Fatalf("ambiguous = %+v", rows[0])
	}

	// A numeric ifIndex skips the name walk. A gap longer than two
	// intervals resets the baseline instead of recording a rate.
	c = mustNew(t, strings.Replace(baseYAML, "interface: ether1", "interface: \"7\"", 1), map[string]string{"PACKETEER_SNMP_COMMUNITY": "lab-community-value"})
	c.dial = func(context.Context, hostSpec) (session, error) {
		return &fakeSession{get: func(oids []string) ([]gosnmp.SnmpPDU, error) {
			var out []gosnmp.SnmpPDU
			for _, oid := range oids {
				switch normOID(oid) {
				case joinOID(oidIfHighSpeed, 7):
					out = append(out, gosnmp.SnmpPDU{Name: "." + oid, Type: gosnmp.Gauge32, Value: uint(10000)})
				case joinOID(oidIfHCInOctets, 7), joinOID(oidIfHCOutOctets, 7):
					out = append(out, pduCounter(normOID(oid), inC, 64))
				case oidSysUpTime:
					out = append(out, gosnmp.SnmpPDU{Name: "." + oid, Type: gosnmp.TimeTicks, Value: uint32(1000)})
				default:
					out = append(out, gosnmp.SnmpPDU{Name: "." + oid, Type: gosnmp.NoSuchInstance})
				}
			}
			return out, nil
		}}, nil
	}
	c.poll(context.Background(), t0)
	inC += 7_500_000
	c.poll(context.Background(), t0.Add(3*c.interval))
	rows, _ = c.Snapshot(context.Background())
	if rows[0].Samples != 0 || rows[0].Error == "" || rows[0].IfIndex != 7 {
		t.Fatalf("gap = %+v", rows[0])
	}
}
