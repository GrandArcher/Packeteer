package offload

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

const recheck = time.Minute

func sample(used, total uint64, at time.Time) Sample {
	return Sample{Reading: Reading{Used: used, Total: total, Known: true}, At: at}
}

func newBudget(t *testing.T, cfg Config) *Budget {
	t.Helper()
	if cfg.Recheck == 0 {
		cfg.Recheck = recheck
	}
	b, err := NewBudget(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var id1 = Identity{Profile: "lab", Version: "1.0"}

func TestEvaluateFreezes(t *testing.T) {
	cfg := Config{Dimensions: []Dimension{FIBv4, NextHops}}
	good := map[Dimension]Sample{
		FIBv4:    sample(100, 1000, t0),
		NextHops: sample(10, 100, t0),
	}
	with := func(d Dimension, s Sample) map[Dimension]Sample {
		m := map[Dimension]Sample{}
		for k, v := range good {
			m[k] = v
		}
		if s == (Sample{}) {
			delete(m, d)
		} else {
			m[d] = s
		}
		return m
	}
	cases := []struct {
		name    string
		now     time.Time
		samples map[Dimension]Sample
		want    []Freeze
	}{
		{"missing dimension", t0, with(NextHops, Sample{}), []Freeze{{FreezeMissing, NextHops}}},
		{"unknown reading", t0, with(FIBv4, Sample{At: t0}), []Freeze{{FreezeMissing, FIBv4}}},
		{"used above cap", t0, with(FIBv4, sample(1001, 1000, t0)), []Freeze{{FreezeInsane, FIBv4}}},
		{"zero cap", t0, with(FIBv4, sample(0, 0, t0)), []Freeze{{FreezeInsane, FIBv4}}},
		{"wrapped negative used", t0, with(FIBv4, sample(^uint64(0), 1000, t0)), []Freeze{{FreezeInsane, FIBv4}}},
		{"wrapped negative cap", t0, with(FIBv4, sample(5, ^uint64(0)-5, t0)), []Freeze{{FreezeInsane, FIBv4}}},
		{"stale", t0.Add(3*recheck + time.Second), good, []Freeze{{FreezeStale, FIBv4}, {FreezeStale, NextHops}}},
		{"no timestamp", t0, with(FIBv4, sample(1, 10, time.Time{})), []Freeze{{FreezeStale, FIBv4}}},
		{"timestamp in the future", t0, with(FIBv4, sample(1, 10, t0.Add(time.Hour))), []Freeze{{FreezeStale, FIBv4}}},
		{"empty samples", t0, nil, []Freeze{{FreezeMissing, FIBv4}, {FreezeMissing, NextHops}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := newBudget(t, cfg).Evaluate(c.now, id1, c.samples)
			if !reflect.DeepEqual(res.Freezes, c.want) {
				t.Fatalf("freezes = %v, want %v", res.Freezes, c.want)
			}
			if !res.Frozen() || res.HeadroomV4 != 0 || res.HeadroomV6 != 0 || res.ShedOK || res.Free != nil {
				t.Errorf("a frozen result must install nothing and never shed: %+v", res)
			}
		})
	}
}

func TestStaleBoundary(t *testing.T) {
	b := newBudget(t, Config{Dimensions: []Dimension{FIBv4}})
	s := map[Dimension]Sample{FIBv4: sample(0, 100, t0)}
	if res := b.Evaluate(t0.Add(3*recheck), id1, s); res.Frozen() {
		t.Errorf("a reading exactly 3 x recheck old is not stale: %v", res.Freezes)
	}
	if res := b.Evaluate(t0.Add(3*recheck+1), id1, s); !res.Frozen() {
		t.Error("a reading older than 3 x recheck must be stale")
	}
}

func TestCapChange(t *testing.T) {
	b := newBudget(t, Config{Dimensions: []Dimension{FIBv4}})
	at := func(i int) time.Time { return t0.Add(time.Duration(i) * recheck) }
	eval := func(i int, id Identity, total uint64) Result {
		return b.Evaluate(at(i), id, map[Dimension]Sample{FIBv4: sample(10, total, at(i))})
	}

	if res := eval(0, id1, 1000); res.Frozen() || res.HeadroomV4 != 990 {
		t.Fatalf("first reading: %+v", res)
	}
	res := eval(1, id1, 2000)
	if !reflect.DeepEqual(res.Freezes, []Freeze{{FreezeInsane, FIBv4}}) {
		t.Fatalf("cap change with the same identity: %+v", res)
	}
	if res := eval(2, id1, 2000); !res.Frozen() {
		t.Error("a changed cap must stay frozen until the identity changes, not for one cycle")
	}
	if res := eval(3, id1, 1000); res.Frozen() {
		t.Errorf("the original cap is trusted again: %v", res.Freezes)
	}
	if res := eval(4, Identity{Profile: "lab", Version: "2.0"}, 2000); res.Frozen() || res.HeadroomV4 != 1990 {
		t.Errorf("a new version may bring a new cap: %+v", res)
	}
	if res := eval(5, Identity{Profile: "other", Version: "2.0"}, 500); res.Frozen() || res.HeadroomV4 != 490 {
		t.Errorf("a new profile may bring a new cap: %+v", res)
	}
	if res := eval(6, Identity{Profile: "other", Version: "2.0"}, 2000); !res.Frozen() {
		t.Error("the baseline must follow the latest identity")
	}
}

func TestInsaneFirstReadingSetsNoBaseline(t *testing.T) {
	b := newBudget(t, Config{Dimensions: []Dimension{FIBv4}})
	if res := b.Evaluate(t0, id1, map[Dimension]Sample{FIBv4: sample(2000, 1000, t0)}); !res.Frozen() {
		t.Fatal("used above cap must freeze")
	}
	if res := b.Evaluate(t0, id1, map[Dimension]Sample{FIBv4: sample(1, 5000, t0)}); res.Frozen() {
		t.Errorf("an insane reading must not become the cap baseline: %v", res.Freezes)
	}
}

func TestFreeAndHeadroom(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		samples map[Dimension]Sample
		free    map[Dimension]uint64
		v4, v6  uint64
		host    uint64
		shed    bool
	}{
		{
			name:    "pct reserve wins",
			cfg:     Config{Dimensions: []Dimension{FIBv4}, Reserve: map[Dimension]Reserve{FIBv4: {Pct: 0.1, Abs: 50}}},
			samples: map[Dimension]Sample{FIBv4: sample(200, 1000, t0)},
			free:    map[Dimension]uint64{FIBv4: 700},
			v4:      700,
		},
		{
			name:    "abs reserve wins",
			cfg:     Config{Dimensions: []Dimension{FIBv4}, Reserve: map[Dimension]Reserve{FIBv4: {Pct: 0.1, Abs: 300}}},
			samples: map[Dimension]Sample{FIBv4: sample(200, 1000, t0)},
			free:    map[Dimension]uint64{FIBv4: 500},
			v4:      500,
		},
		{
			name:    "pct reserve rounds up",
			cfg:     Config{Dimensions: []Dimension{FIBv4}, Reserve: map[Dimension]Reserve{FIBv4: {Pct: 0.1}}},
			samples: map[Dimension]Sample{FIBv4: sample(0, 15, t0)},
			free:    map[Dimension]uint64{FIBv4: 13},
			v4:      13,
		},
		{
			name:    "used inside reserve is zero free, shed allowed",
			cfg:     Config{Dimensions: []Dimension{FIBv4}, Reserve: map[Dimension]Reserve{FIBv4: {Abs: 100}}},
			samples: map[Dimension]Sample{FIBv4: sample(950, 1000, t0)},
			free:    map[Dimension]uint64{FIBv4: 0},
			shed:    true,
		},
		{
			name:    "used equals cap",
			cfg:     Config{Dimensions: []Dimension{FIBv4}},
			samples: map[Dimension]Sample{FIBv4: sample(1000, 1000, t0)},
			free:    map[Dimension]uint64{FIBv4: 0},
			shed:    true,
		},
		{
			name:    "reserve larger than the cap",
			cfg:     Config{Dimensions: []Dimension{FIBv4}, Reserve: map[Dimension]Reserve{FIBv4: {Abs: ^uint64(0)}}},
			samples: map[Dimension]Sample{FIBv4: sample(0, 1000, t0)},
			free:    map[Dimension]uint64{FIBv4: 0},
			shed:    true,
		},
		{
			name: "smallest free across dimensions",
			cfg:  Config{Dimensions: []Dimension{FIBv4, NextHops, ECMPGroups}},
			samples: map[Dimension]Sample{
				FIBv4:      sample(0, 1000, t0),
				NextHops:   sample(90, 100, t0),
				ECMPGroups: sample(0, 64, t0),
			},
			free: map[Dimension]uint64{FIBv4: 1000, NextHops: 10, ECMPGroups: 64},
			v4:   10,
			host: 10,
		},
		{
			name: "cpu has headroom: it gates but does not bound",
			cfg:  Config{Dimensions: []Dimension{FIBv4, CPU}, Reserve: map[Dimension]Reserve{CPU: {Abs: 20}}},
			samples: map[Dimension]Sample{
				FIBv4: sample(0, 1000, t0),
				CPU:   sample(50, 100, t0),
			},
			free: map[Dimension]uint64{FIBv4: 1000, CPU: 30},
			v4:   1000,
		},
		{
			name: "cpu without headroom blocks installs",
			cfg:  Config{Dimensions: []Dimension{FIBv4, CPU}, Reserve: map[Dimension]Reserve{CPU: {Abs: 20}}},
			samples: map[Dimension]Sample{
				FIBv4: sample(0, 1000, t0),
				CPU:   sample(80, 100, t0),
			},
			free: map[Dimension]uint64{FIBv4: 1000, CPU: 0},
			shed: true,
		},
		{
			name: "separate IPv6 pool",
			cfg:  Config{Dimensions: []Dimension{FIBv4, FIBv6, NextHops}},
			samples: map[Dimension]Sample{
				FIBv4:    sample(100, 1000, t0),
				FIBv6:    sample(450, 500, t0),
				NextHops: sample(0, 300, t0),
			},
			free: map[Dimension]uint64{FIBv4: 900, FIBv6: 50, NextHops: 300},
			v4:   300,
			v6:   50,
			host: 300,
		},
		{
			name: "separate IPv6 pool full does not stop IPv4",
			cfg:  Config{Dimensions: []Dimension{FIBv4, FIBv6}},
			samples: map[Dimension]Sample{
				FIBv4: sample(100, 1000, t0),
				FIBv6: sample(500, 500, t0),
			},
			free: map[Dimension]uint64{FIBv4: 900, FIBv6: 0},
			v4:   900,
			v6:   0,
			shed: true,
		},
		{
			name:    "shared IPv6 pool at double cost",
			cfg:     Config{Dimensions: []Dimension{FIBv4}, IPv6: IPv6Pool{Shared: true, Weight: 2}},
			samples: map[Dimension]Sample{FIBv4: sample(100, 1001, t0)},
			free:    map[Dimension]uint64{FIBv4: 901},
			v4:      901,
			v6:      450,
		},
		{
			name: "shared IPv6 pool still bound by next hops",
			cfg: Config{Dimensions: []Dimension{FIBv4, NextHops},
				IPv6: IPv6Pool{Shared: true, Weight: 4}},
			samples: map[Dimension]Sample{
				FIBv4:    sample(0, 1000, t0),
				NextHops: sample(95, 100, t0),
			},
			free: map[Dimension]uint64{FIBv4: 1000, NextHops: 5},
			v4:   5,
			v6:   5,
			host: 5,
		},
		{
			name:    "no IPv6 dimension means no IPv6 installs",
			cfg:     Config{Dimensions: []Dimension{FIBv4, NextHops}},
			samples: map[Dimension]Sample{FIBv4: sample(0, 1000, t0), NextHops: sample(0, 100, t0)},
			free:    map[Dimension]uint64{FIBv4: 1000, NextHops: 100},
			v4:      100,
			host:    100,
		},
		{
			name: "a full FIB leaves room for host entries",
			cfg:  Config{Dimensions: []Dimension{FIBv4, NextHops}},
			samples: map[Dimension]Sample{
				FIBv4:    sample(1000, 1000, t0),
				NextHops: sample(60, 100, t0),
			},
			free: map[Dimension]uint64{FIBv4: 0, NextHops: 40},
			host: 40,
			shed: true,
		},
		{
			name: "cpu without headroom blocks host entries",
			cfg:  Config{Dimensions: []Dimension{FIBv4, NextHops, CPU}, Reserve: map[Dimension]Reserve{CPU: {Abs: 20}}},
			samples: map[Dimension]Sample{
				FIBv4:    sample(0, 1000, t0),
				NextHops: sample(0, 100, t0),
				CPU:      sample(80, 100, t0),
			},
			free: map[Dimension]uint64{FIBv4: 1000, NextHops: 100, CPU: 0},
			shed: true,
		},
		{
			name:    "no IPv4 dimension means no IPv4 installs",
			cfg:     Config{Dimensions: []Dimension{FIBv6}},
			samples: map[Dimension]Sample{FIBv6: sample(0, 500, t0)},
			free:    map[Dimension]uint64{FIBv6: 500},
			v6:      500,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := newBudget(t, c.cfg).Evaluate(t0, id1, c.samples)
			if res.Frozen() {
				t.Fatalf("unexpected freeze: %v", res.Freezes)
			}
			if !reflect.DeepEqual(res.Free, c.free) {
				t.Errorf("free = %v, want %v", res.Free, c.free)
			}
			if res.HeadroomV4 != c.v4 || res.HeadroomV6 != c.v6 {
				t.Errorf("headroom v4/v6 = %d/%d, want %d/%d", res.HeadroomV4, res.HeadroomV6, c.v4, c.v6)
			}
			if res.HeadroomHost != c.host {
				t.Errorf("host headroom = %d, want %d", res.HeadroomHost, c.host)
			}
			if res.ShedOK != c.shed {
				t.Errorf("ShedOK = %v, want %v", res.ShedOK, c.shed)
			}
		})
	}
}

func TestIgnoresSamplesForUnlistedDimensions(t *testing.T) {
	b := newBudget(t, Config{Dimensions: []Dimension{FIBv4}})
	res := b.Evaluate(t0, id1, map[Dimension]Sample{
		FIBv4:      sample(0, 10, t0),
		ECMPGroups: sample(99, 1, t0),
	})
	if res.Frozen() {
		t.Errorf("a sample for a dimension the profile does not budget must be ignored: %v", res.Freezes)
	}
}

func TestNewBudgetValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"no recheck", Config{Dimensions: []Dimension{FIBv4}}, "recheck"},
		{"no dimensions", Config{Recheck: recheck}, "no dimensions"},
		{"unknown dimension", Config{Recheck: recheck, Dimensions: []Dimension{"tcam"}}, "unknown dimension"},
		{"duplicate dimension", Config{Recheck: recheck, Dimensions: []Dimension{FIBv4, FIBv4}}, "twice"},
		{"reserve for unlisted", Config{Recheck: recheck, Dimensions: []Dimension{FIBv4}, Reserve: map[Dimension]Reserve{CPU: {Abs: 1}}}, "unlisted"},
		{"reserve pct above 1", Config{Recheck: recheck, Dimensions: []Dimension{FIBv4}, Reserve: map[Dimension]Reserve{FIBv4: {Pct: 1.5}}}, "pct"},
		{"reserve pct negative", Config{Recheck: recheck, Dimensions: []Dimension{FIBv4}, Reserve: map[Dimension]Reserve{FIBv4: {Pct: -0.1}}}, "pct"},
		{"shared with own pool", Config{Recheck: recheck, Dimensions: []Dimension{FIBv4, FIBv6}, IPv6: IPv6Pool{Shared: true, Weight: 2}}, "exclusive"},
		{"shared without fib v4", Config{Recheck: recheck, Dimensions: []Dimension{NextHops}, IPv6: IPv6Pool{Shared: true, Weight: 2}}, "needs"},
		{"shared without weight", Config{Recheck: recheck, Dimensions: []Dimension{FIBv4}, IPv6: IPv6Pool{Shared: true}}, "weight"},
		{"weight without shared", Config{Recheck: recheck, Dimensions: []Dimension{FIBv4}, IPv6: IPv6Pool{Weight: 2}}, "weight"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewBudget(c.cfg)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want one containing %q", err, c.want)
			}
		})
	}
}

type funcReader func(Dimension) (Reading, error)

func (f funcReader) Read(_ context.Context, d Dimension) (Reading, error) { return f(d) }

// A reader that cannot answer must freeze, whatever it hands back alongside
// the failure: no outcome of a dead reader may allow a shed.
func TestDeadReaderNeverSheds(t *testing.T) {
	// Values that would look like a full table if they were trusted.
	full := Reading{Used: 1000, Total: 1000, Known: true}
	cases := []struct {
		name string
		r    Reader
	}{
		{"nil reader", nil},
		{"unknown reading", fakeReader{}},
		{"error with a full reading", funcReader(func(Dimension) (Reading, error) { return full, errors.New("snmp timeout") })},
		{"panic", funcReader(func(Dimension) (Reading, error) { panic("boom") })},
	}
	dims := []Dimension{FIBv4, NextHops}
	b := newBudget(t, Config{Dimensions: dims})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := b.Evaluate(t0, id1, Collect(context.Background(), c.r, dims, t0))
			want := []Freeze{{FreezeMissing, FIBv4}, {FreezeMissing, NextHops}}
			if !reflect.DeepEqual(res.Freezes, want) {
				t.Fatalf("freezes = %v, want %v", res.Freezes, want)
			}
			if res.ShedOK || res.HeadroomV4 != 0 || res.HeadroomV6 != 0 {
				t.Errorf("dead reader produced a decision: %+v", res)
			}
		})
	}
}

func TestCollectKeepsGoodReadings(t *testing.T) {
	r := funcReader(func(d Dimension) (Reading, error) {
		if d == NextHops {
			return Reading{}, errors.New("timeout")
		}
		return Reading{Used: 5, Total: 50, Known: true}, nil
	})
	got := Collect(context.Background(), r, []Dimension{FIBv4, NextHops}, t0)
	if want := sample(5, 50, t0); got[FIBv4] != want {
		t.Errorf("FIBv4 = %+v, want %+v", got[FIBv4], want)
	}
	if got[NextHops].Known {
		t.Errorf("a failed read must be unknown: %+v", got[NextHops])
	}
	res := newBudget(t, Config{Dimensions: []Dimension{FIBv4, NextHops}}).Evaluate(t0, id1, got)
	if !reflect.DeepEqual(res.Freezes, []Freeze{{FreezeMissing, NextHops}}) || res.ShedOK {
		t.Errorf("one failed dimension must freeze the whole budget: %+v", res)
	}
}

func TestHealthyReaderEndToEnd(t *testing.T) {
	r := funcReader(func(d Dimension) (Reading, error) {
		return Reading{Used: 100, Total: 1000, Known: true}, nil
	})
	dims := []Dimension{FIBv4, FIBv6}
	res := newBudget(t, Config{Dimensions: dims, Reserve: map[Dimension]Reserve{FIBv4: {Pct: 0.1}}}).
		Evaluate(t0, id1, Collect(context.Background(), r, dims, t0))
	if res.Frozen() || res.HeadroomV4 != 800 || res.HeadroomV6 != 900 || res.ShedOK {
		t.Errorf("result = %+v", res)
	}
}
