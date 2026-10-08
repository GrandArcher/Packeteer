package snmp

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/GrandArcher/Packeteer/internal/plugins/storage/sqlite"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const persistYAML = `
interval: 30s
timeout: 1s
retries: 0
hosts:
  - name: edge
    address: 192.0.2.254
    version: 2c
    community_env: PACKETEER_SNMP_COMMUNITY
providers:
  - name: transit-a
    host: edge
    interface: ether1
    commit_mbps: 1000
    billing_day: 1
    percentile: greater_separate
  - name: transit-b
    host: edge
    interface: ether2
    commit_mbps: 500
    billing_day: 15
    percentile: separate
`

func testEnv() map[string]string {
	return map[string]string{"PACKETEER_SNMP_COMMUNITY": "lab-community-value"}
}

func openDB(t *testing.T, path string) *sqlite.Store {
	t.Helper()
	c, err := plugin.ConfigFromYAML("path: " + path + "\nretention: 87600h\n")
	if err != nil {
		t.Fatal(err)
	}
	s, err := sqlite.New(c, plugin.Env{Logger: discardLog()})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

func stopPair(c *Collector, s *sqlite.Store) {
	if c != nil {
		_ = c.Stop(context.Background())
	}
	if s != nil {
		_ = s.Stop(context.Background())
	}
}

func noAgent(c *Collector) {
	c.dial = func(context.Context, hostSpec) (session, error) {
		return nil, errors.New("no agent")
	}
}

func atClock(c *Collector, now time.Time) {
	c.now = func() time.Time { return now }
}

func usageOf(t *testing.T, c *Collector, provider string) plugin.Usage {
	t.Helper()
	rows, err := c.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Provider == provider {
			return r
		}
	}
	t.Fatalf("no usage for %s", provider)
	return plugin.Usage{}
}

func same95(t *testing.T, got, want plugin.Usage) {
	t.Helper()
	if got.Samples != want.Samples || got.InMbps95 != want.InMbps95 || got.OutMbps95 != want.OutMbps95 ||
		got.UsageMbps != want.UsageMbps || got.Single != want.Single || got.InMbps != want.InMbps || got.OutMbps != want.OutMbps ||
		!got.Updated.Equal(want.Updated) {
		t.Fatalf("got samples %d in95 %v out95 %v usage %v single %v rate %v/%v updated %s\nwant samples %d in95 %v out95 %v usage %v single %v rate %v/%v updated %s",
			got.Samples, got.InMbps95, got.OutMbps95, got.UsageMbps, got.Single, got.InMbps, got.OutMbps, got.Updated,
			want.Samples, want.InMbps95, want.OutMbps95, want.UsageMbps, want.Single, want.InMbps, want.OutMbps, want.Updated)
	}
}

// TestSamplesSurviveRestart writes a billing window, closes the database,
// and opens a new collector on the same file. The 95th matches, per binding.
func TestSamplesSurviveRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "packeteer.db")
	s := openDB(t, path)
	c := mustNew(t, persistYAML, testEnv())
	c.UseSampleStore(s)
	// 2026-10-07 is inside billing day 1 (Oct 1–Nov 1) and day 15 (Sep 15–Oct 15).
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	atClock(c, now)
	for i := 0; i < 20; i++ {
		at := time.Date(2026, 10, 2, i, 0, 0, 0, time.UTC)
		c.addSample("transit-a", at, float64(i+1)*1e6, float64(i+1)*1e6)
		atB := time.Date(2026, 9, 20, i, 0, 0, 0, time.UTC)
		c.addSample("transit-b", atB, float64(i+1)*1e6, float64(i+1)*0.5e6)
	}
	beforeA := usageOf(t, c, "transit-a")
	beforeB := usageOf(t, c, "transit-b")
	// N of 20, nearest rank 19: not the maximum. Both directions, and separate has no combined figure.
	if beforeA.Samples != 20 || beforeA.InMbps95 != 19 || beforeA.UsageMbps != 19 || !beforeA.Single {
		t.Fatalf("before restart transit-a = %+v", beforeA)
	}
	if beforeB.Samples != 20 || beforeB.InMbps95 != 19 || beforeB.OutMbps95 != 9.5 || beforeB.Single || beforeB.UsageMbps != 0 {
		t.Fatalf("before restart transit-b = %+v", beforeB)
	}
	stopPair(c, s)

	s2 := openDB(t, path)
	defer stopPair(nil, s2)
	c2 := mustNew(t, persistYAML, testEnv())
	c2.UseSampleStore(s2)
	atClock(c2, now)
	noAgent(c2)
	if err := c2.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer c2.Stop(ctx)
	same95(t, usageOf(t, c2, "transit-a"), beforeA)
	same95(t, usageOf(t, c2, "transit-b"), beforeB)
}

// TestNoStorageDoesNotPersist is the restart behavior when no storage
// plugin is configured: the new process starts from an empty window.
func TestNoStorageDoesNotPersist(t *testing.T) {
	c := mustNew(t, persistYAML, testEnv())
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	atClock(c, now)
	c.addSample("transit-a", now.Add(-time.Hour), 5e6, 5e6)
	if usageOf(t, c, "transit-a").Samples != 1 {
		t.Fatal("sample was not kept in memory")
	}
	c2 := mustNew(t, persistYAML, testEnv())
	atClock(c2, now)
	noAgent(c2)
	if err := c2.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer c2.Stop(context.Background())
	if got := usageOf(t, c2, "transit-a"); got.Samples != 0 || got.UsageMbps != 0 {
		t.Fatalf("restart without storage = %+v", got)
	}
}

// TestPeriodRolloverPrunesAndMaxSamples checks that crossing the billing
// day drops the closed period from the live window and from what a restart
// loads, while the closed period stays in the database, and that
// max_samples caps memory and the open period on disk.
func TestPeriodRolloverPrunesAndMaxSamples(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "packeteer.db")
	s := openDB(t, path)
	defer stopPair(nil, s)
	yml := `
interval: 30s
timeout: 1s
retries: 0
max_samples: 3
hosts:
  - name: edge
    address: 192.0.2.254
    version: 2c
    community_env: PACKETEER_SNMP_COMMUNITY
providers:
  - name: transit-a
    host: edge
    interface: ether1
    commit_mbps: 1000
    billing_day: 15
    percentile: greater_separate
`
	c := mustNew(t, yml, testEnv())
	c.UseSampleStore(s)
	march := time.Date(2026, 3, 14, 23, 0, 0, 0, time.UTC)
	atClock(c, march)
	for i := 0; i < 8; i++ {
		c.addSample("transit-a", time.Date(2026, 3, 14, i, 0, 0, 0, time.UTC), float64(i+1)*1e6, float64(i+1)*1e6)
		c.mu.Lock()
		n := len(c.states["transit-a"].win.samples)
		c.mu.Unlock()
		if n > 3 {
			t.Fatalf("memory grew to %d", n)
		}
	}
	c.mu.Lock()
	n := len(c.states["transit-a"].win.samples)
	oldest := c.states["transit-a"].win.samples[0].in
	c.mu.Unlock()
	if n != 3 || oldest != 6e6 {
		t.Fatalf("window len %d oldest %v, want 3 and 6e6", n, oldest)
	}
	// Rank of 3 is the maximum, 8 Mbps. The dropped 1 Mbps sample must not come back.
	before := usageOf(t, c, "transit-a")
	if before.Samples != 3 || before.UsageMbps != 8 {
		t.Fatalf("capped window = %+v", before)
	}
	start, end := billingPeriod(march, 15)
	rows, err := s.UsageSamples(ctx, plugin.UsageSampleQuery{
		Provider: "transit-a", Host: "edge", Interface: "ether1", From: start, To: end,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[0].InBps != 6e6 || rows[2].InBps != 8e6 {
		t.Fatalf("stored open period = %+v", rows)
	}

	april := time.Date(2026, 3, 15, 0, 30, 0, 0, time.UTC)
	atClock(c, april)
	c.addSample("transit-a", april, 3e6, 1e6)
	c.mu.Lock()
	n = len(c.states["transit-a"].win.samples)
	c.mu.Unlock()
	if n != 1 {
		t.Fatalf("after rollover memory = %d, want 1", n)
	}
	rolled := usageOf(t, c, "transit-a")
	if rolled.Samples != 1 || rolled.InMbps95 != 3 || rolled.UsageMbps != 3 {
		t.Fatalf("rolled = %+v", rolled)
	}
	// The closed period is still on disk for a later report.
	closed, err := s.UsageSamples(ctx, plugin.UsageSampleQuery{
		Provider: "transit-a", Host: "edge", Interface: "ether1", From: start, To: end,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(closed) != 3 {
		t.Fatalf("closed period rows = %d, want 3 kept", len(closed))
	}

	stopPair(c, s)
	s2 := openDB(t, path)
	defer stopPair(nil, s2)
	c2 := mustNew(t, yml, testEnv())
	c2.UseSampleStore(s2)
	atClock(c2, april)
	noAgent(c2)
	if err := c2.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer c2.Stop(ctx)
	same95(t, usageOf(t, c2, "transit-a"), rolled)
	// A restart does not load the closed period back into the 95th.
	if usageOf(t, c2, "transit-a").Samples != 1 {
		t.Fatal("closed period was loaded")
	}
}

// TestPollSampleSurvivesRestart goes through a real poll, not addSample,
// then a new collector on the same database.
func TestPollSampleSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "packeteer.db")
	s := openDB(t, path)
	c := mustNew(t, persistYAML, testEnv())
	c.UseSampleStore(s)
	var inC, outC uint64 = 1000, 1000
	c.dial = func(context.Context, hostSpec) (session, error) {
		return &fakeSession{
			walk: func(oid string) ([]gosnmp.SnmpPDU, error) {
				if normOID(oid) != oidIfName {
					return nil, nil
				}
				return []gosnmp.SnmpPDU{
					{Name: "." + joinOID(oidIfName, 5), Type: gosnmp.OctetString, Value: "ether1"},
					{Name: "." + joinOID(oidIfName, 6), Type: gosnmp.OctetString, Value: "ether2"},
				}, nil
			},
			get: func(oids []string) ([]gosnmp.SnmpPDU, error) {
				var out []gosnmp.SnmpPDU
				for _, oid := range oids {
					switch normOID(oid) {
					case joinOID(oidIfHighSpeed, 5), joinOID(oidIfHighSpeed, 6):
						out = append(out, gosnmp.SnmpPDU{Name: "." + oid, Type: gosnmp.Gauge32, Value: uint(1000)})
					case joinOID(oidIfHCInOctets, 5), joinOID(oidIfHCInOctets, 6):
						out = append(out, pduCounter(normOID(oid), inC, 64))
					case joinOID(oidIfHCOutOctets, 5), joinOID(oidIfHCOutOctets, 6):
						out = append(out, pduCounter(normOID(oid), outC, 64))
					case oidSysUpTime:
						out = append(out, gosnmp.SnmpPDU{Name: "." + oid, Type: gosnmp.TimeTicks, Value: uint32(10_000)})
					default:
						out = append(out, gosnmp.SnmpPDU{Name: "." + oid, Type: gosnmp.NoSuchInstance})
					}
				}
				return out, nil
			},
		}, nil
	}
	t0 := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Minute)
	atClock(c, t1)
	c.poll(context.Background(), t0)
	if usageOf(t, c, "transit-a").Samples != 0 {
		t.Fatal("baseline stored a sample")
	}
	inC += 7_500_000
	outC += 15_000_000
	c.poll(context.Background(), t1)
	before := usageOf(t, c, "transit-a")
	if before.Samples != 1 || before.InMbps95 != 1 || before.OutMbps95 != 2 || before.UsageMbps != 2 {
		t.Fatalf("polled = %+v", before)
	}
	stopPair(c, s)

	s2 := openDB(t, path)
	defer stopPair(nil, s2)
	c2 := mustNew(t, persistYAML, testEnv())
	c2.UseSampleStore(s2)
	atClock(c2, t1)
	noAgent(c2)
	if err := c2.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer c2.Stop(context.Background())
	same95(t, usageOf(t, c2, "transit-a"), before)
}

// TestSamplesRestoredFromBackup copies the database out and back. The
// open period's 95th is the same one that was backed up.
func TestSamplesRestoredFromBackup(t *testing.T) {
	ctx := context.Background()
	s := openDB(t, filepath.Join(t.TempDir(), "packeteer.db"))
	c := mustNew(t, persistYAML, testEnv())
	c.UseSampleStore(s)
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	atClock(c, now)
	for i := 0; i < 20; i++ {
		c.addSample("transit-a", time.Date(2026, 10, 2, i, 0, 0, 0, time.UTC), float64(i+1)*1e6, float64(i+1)*1e6)
	}
	before := usageOf(t, c, "transit-a")
	var buf bytes.Buffer
	if err := s.Backup(ctx, &buf); err != nil {
		t.Fatal(err)
	}
	stopPair(c, s)

	dstPath := filepath.Join(t.TempDir(), "restored", "packeteer.db")
	dst := openDB(t, dstPath)
	// openDB already created an empty file. Restore refuses unless forced,
	// which is the same rule as history. Replace it.
	if err := dst.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	dst = newRestoreStore(t, dstPath)
	if err := dst.Restore(ctx, bytes.NewReader(buf.Bytes()), true); err != nil {
		t.Fatal(err)
	}
	if err := dst.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer stopPair(nil, dst)
	c2 := mustNew(t, persistYAML, testEnv())
	c2.UseSampleStore(dst)
	atClock(c2, now)
	noAgent(c2)
	if err := c2.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer c2.Stop(ctx)
	same95(t, usageOf(t, c2, "transit-a"), before)
}

func newRestoreStore(t *testing.T, path string) *sqlite.Store {
	t.Helper()
	c, err := plugin.ConfigFromYAML("path: " + path + "\nretention: 87600h\n")
	if err != nil {
		t.Fatal(err)
	}
	s, err := sqlite.New(c, plugin.Env{Logger: discardLog()})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
