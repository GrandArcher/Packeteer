package snmp

import (
	"context"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// agent is an in-process SNMPv2c responder for the OIDs the collector reads.
// It is not a general agent. Tests use it instead of a live network.
type agent struct {
	conn      *net.UDPConn
	community string
	mu        sync.Mutex
	vars      []agentVar
}

type agentVar struct {
	oid string
	pdu gosnmp.SnmpPDU
}

func startAgent(t *testing.T, community string) *agent {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	a := &agent{conn: conn, community: community}
	go a.serve()
	t.Cleanup(func() { _ = conn.Close() })
	return a
}

func (a *agent) port() int { return a.conn.LocalAddr().(*net.UDPAddr).Port }

func (a *agent) set(oid string, typ gosnmp.Asn1BER, val any) {
	oid = normOID(oid)
	pdu := gosnmp.SnmpPDU{Name: "." + oid, Type: typ, Value: val}
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.vars {
		if a.vars[i].oid == oid {
			a.vars[i].pdu = pdu
			return
		}
	}
	a.vars = append(a.vars, agentVar{oid: oid, pdu: pdu})
	// Insertion sort keeps GETBULK in OID order.
	for i := len(a.vars) - 1; i > 0 && oidLess(a.vars[i].oid, a.vars[i-1].oid); i-- {
		a.vars[i], a.vars[i-1] = a.vars[i-1], a.vars[i]
	}
}

func (a *agent) serve() {
	buf := make([]byte, 65535)
	dec := &gosnmp.GoSNMP{Version: gosnmp.Version2c}
	for {
		_ = a.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, addr, err := a.conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		pkt, err := dec.UnmarshalTrap(append([]byte(nil), buf[:n]...), false)
		if err != nil || pkt.Version != gosnmp.Version2c || pkt.Community != a.community {
			continue
		}
		resp := a.answer(pkt)
		raw, err := resp.MarshalMsg()
		if err != nil {
			continue
		}
		_, _ = a.conn.WriteToUDP(raw, addr)
	}
}

func (a *agent) answer(req *gosnmp.SnmpPacket) *gosnmp.SnmpPacket {
	vars := a.bindings(req)
	return &gosnmp.SnmpPacket{
		Version:   gosnmp.Version2c,
		Community: a.community,
		PDUType:   gosnmp.GetResponse,
		RequestID: req.RequestID,
		Variables: vars,
	}
}

func (a *agent) bindings(req *gosnmp.SnmpPacket) []gosnmp.SnmpPDU {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch req.PDUType {
	case gosnmp.GetRequest:
		out := make([]gosnmp.SnmpPDU, 0, len(req.Variables))
		for _, v := range req.Variables {
			if p, ok := a.exact(normOID(v.Name)); ok {
				out = append(out, p)
				continue
			}
			out = append(out, gosnmp.SnmpPDU{Name: v.Name, Type: gosnmp.NoSuchInstance})
		}
		return out
	case gosnmp.GetNextRequest:
		if len(req.Variables) == 0 {
			return nil
		}
		return []gosnmp.SnmpPDU{a.next(normOID(req.Variables[0].Name))}
	case gosnmp.GetBulkRequest:
		maxRep := int(req.MaxRepetitions)
		if maxRep < 1 {
			maxRep = 1
		}
		if maxRep > 20 {
			maxRep = 20
		}
		if len(req.Variables) == 0 {
			return nil
		}
		cur := normOID(req.Variables[0].Name)
		out := make([]gosnmp.SnmpPDU, 0, maxRep)
		for i := 0; i < maxRep; i++ {
			p := a.next(cur)
			out = append(out, p)
			if p.Type == gosnmp.EndOfMibView {
				break
			}
			cur = normOID(p.Name)
		}
		return out
	default:
		return []gosnmp.SnmpPDU{{Name: ".1.3", Type: gosnmp.NoSuchObject}}
	}
}

func (a *agent) exact(oid string) (gosnmp.SnmpPDU, bool) {
	for _, v := range a.vars {
		if v.oid == oid {
			return v.pdu, true
		}
	}
	return gosnmp.SnmpPDU{}, false
}

func (a *agent) next(oid string) gosnmp.SnmpPDU {
	for _, v := range a.vars {
		if oidLess(oid, v.oid) {
			return v.pdu
		}
	}
	name := oid
	if !strings.HasPrefix(name, ".") {
		name = "." + name
	}
	return gosnmp.SnmpPDU{Name: name, Type: gosnmp.EndOfMibView}
}

func oidLess(a, b string) bool {
	as, bs := splitOID(a), splitOID(b)
	n := len(as)
	if len(bs) < n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		if as[i] != bs[i] {
			return as[i] < bs[i]
		}
	}
	return len(as) < len(bs)
}

func splitOID(s string) []int {
	s = normOID(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	return out
}

func loadIface(a *agent, index int, name string, speedMbps uint32, hc bool) {
	a.set(joinOID(oidIfName, index), gosnmp.OctetString, name)
	a.set(joinOID(oidIfDescr, index), gosnmp.OctetString, name)
	a.set(joinOID(oidIfHighSpeed, index), gosnmp.Gauge32, speedMbps)
	a.set(joinOID(oidIfSpeed, index), gosnmp.Gauge32, speedMbps*1_000_000)
	if hc {
		a.set(joinOID(oidIfHCInOctets, index), gosnmp.Counter64, uint64(0))
		a.set(joinOID(oidIfHCOutOctets, index), gosnmp.Counter64, uint64(0))
	}
	a.set(joinOID(oidIfInOctets, index), gosnmp.Counter32, uint32(0))
	a.set(joinOID(oidIfOutOctets, index), gosnmp.Counter32, uint32(0))
	a.set(oidSysUpTime, gosnmp.TimeTicks, uint32(100000))
}

func TestAgentCollectsRateAnd95th(t *testing.T) {
	const community = "lab-community-value"
	a := startAgent(t, community)
	loadIface(a, 5, "ether1", 1000, true)
	// 32-bit counters disagree with the 64-bit ones. The collector must
	// use the 64-bit pair.
	a.set(joinOID(oidIfInOctets, 5), gosnmp.Counter32, uint32(1))
	a.set(joinOID(oidIfOutOctets, 5), gosnmp.Counter32, uint32(1))

	yml := strings.Replace(baseYAML, "address: 192.0.2.254", fmt.Sprintf("address: 127.0.0.1\n    port: %d", a.port()), 1)
	c := mustNew(t, yml, map[string]string{"PACKETEER_SNMP_COMMUNITY": community})

	t0 := time.Now().UTC()
	c.poll(context.Background(), t0)
	rows, err := c.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].Error != "" || rows[0].IfIndex != 5 || rows[0].Samples != 0 {
		t.Fatalf("baseline = %+v", rows[0])
	}
	if strings.Contains(rows[0].Error, community) {
		t.Fatal("error contains the community")
	}

	a.set(joinOID(oidIfHCInOctets, 5), gosnmp.Counter64, uint64(7_500_000))
	a.set(joinOID(oidIfHCOutOctets, 5), gosnmp.Counter64, uint64(15_000_000))
	a.set(oidSysUpTime, gosnmp.TimeTicks, uint32(100000+6000))
	c.poll(context.Background(), t0.Add(time.Minute))
	rows, _ = c.Snapshot(context.Background())
	if rows[0].Error != "" || rows[0].Samples != 1 || math.Abs(rows[0].InMbps-1) > 0.02 || math.Abs(rows[0].OutMbps-2) > 0.02 {
		t.Fatalf("sample = %+v", rows[0])
	}
	if !rows[0].Single || math.Abs(rows[0].UsageMbps-2) > 0.02 {
		t.Fatalf("95th = %+v", rows[0])
	}
	if c.states["transit-a"].bits != 64 {
		t.Fatalf("bits = %d, want 64", c.states["transit-a"].bits)
	}
}

func TestAgent32BitFallbackAndBadCommunity(t *testing.T) {
	const community = "lab-community-value"
	a := startAgent(t, community)
	loadIface(a, 3, "ether2", 100, false)

	yml := strings.Replace(baseYAML, "interface: ether1", "interface: ether2", 1)
	yml = strings.Replace(yml, "percentile: greater_separate", "percentile: separate", 1)
	yml = strings.Replace(yml, "address: 192.0.2.254", fmt.Sprintf("address: 127.0.0.1\n    port: %d", a.port()), 1)
	c := mustNew(t, yml, map[string]string{"PACKETEER_SNMP_COMMUNITY": community})

	t0 := time.Now().UTC()
	// 32-bit wrap: 2^32-1000, then 6500, delta 7500 octets, 1000 bps over 60s.
	const base = uint32(0xffffffff) - 999
	a.set(joinOID(oidIfInOctets, 3), gosnmp.Counter32, base)
	a.set(joinOID(oidIfOutOctets, 3), gosnmp.Counter32, base)
	c.poll(context.Background(), t0)
	a.set(joinOID(oidIfInOctets, 3), gosnmp.Counter32, uint32(6500))
	a.set(joinOID(oidIfOutOctets, 3), gosnmp.Counter32, uint32(6500))
	a.set(oidSysUpTime, gosnmp.TimeTicks, uint32(100000+6000))
	c.poll(context.Background(), t0.Add(time.Minute))
	rows, _ := c.Snapshot(context.Background())
	if rows[0].Error != "" || c.states["transit-a"].bits != 32 || math.Abs(rows[0].InMbps-0.001) > 0.0001 {
		t.Fatalf("32-bit = %+v bits %d", rows[0], c.states["transit-a"].bits)
	}
	if rows[0].Single || rows[0].Mode != plugin.PercentileSeparate || rows[0].UsageMbps != 0 {
		t.Fatalf("separate usage = %+v", rows[0])
	}

	wrong := mustNew(t, strings.Replace(yml, "timeout: 1s", "timeout: 200ms", 1), map[string]string{"PACKETEER_SNMP_COMMUNITY": "not-the-community"})
	wrong.poll(context.Background(), t0)
	rows, _ = wrong.Snapshot(context.Background())
	if rows[0].Error == "" || strings.Contains(rows[0].Error, "not-the-community") || strings.Contains(rows[0].Error, community) {
		t.Fatalf("bad community error = %q", rows[0].Error)
	}
}

func TestStopCancelsPoll(t *testing.T) {
	c := mustNew(t, baseYAML, map[string]string{"PACKETEER_SNMP_COMMUNITY": "lab-community-value"})
	started := make(chan struct{})
	c.dial = func(ctx context.Context, h hostSpec) (session, error) {
		select {
		case <-started:
		default:
			close(started)
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("poll did not start")
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()
	if err := c.Stop(stopCtx); err != nil {
		t.Fatal(err)
	}
}
