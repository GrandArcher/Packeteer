package main

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strings"
	"time"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time        { return c.now }
func (c *fakeClock) Sleep(d time.Duration) { c.now = c.now.Add(d) }

// fakeHoldMs is the simulated negotiated hold time.
const fakeHoldMs = 3000

type fakeInst struct {
	running, terminating bool
	adminDown, session   bool
	exitCode             int
	// advertised is what the speaker last sent; a killed process's
	// routes stay as they were until the session drops.
	advertised bool
	updates    int64
}

// fakeLab simulates the HA lab: an edge and an active/standby pair on one
// lease, timed by the fake clock. The break fields make it misbehave the
// way a broken controller or router would.
type fakeLab struct {
	clk      *fakeClock
	in       [2]*fakeInst
	holder   int
	probesUp bool
	pending  []fakeEvent

	termNoWithdraw bool // SIGTERM exits without withdrawing first
	gr             bool // pk-a's session carries graceful restart
	both           bool // the standby announces too
	unlearned      bool // pk-a also announces a prefix the edge never had
	keepAfterKill  bool // the edge keeps a killed peer's routes (stale retention)
	termExit       int  // the exit code after SIGTERM
	probeFiles     []string
}

type fakeEvent struct {
	at time.Time
	do func()
}

func newFakeLab(clk *fakeClock) *fakeLab {
	l := &fakeLab{clk: clk, holder: 0, probesUp: true}
	for i := range l.in {
		l.in[i] = &fakeInst{running: true, session: true}
	}
	return l
}

func (l *fakeLab) after(d time.Duration, do func()) {
	l.pending = append(l.pending, fakeEvent{at: l.clk.now.Add(d), do: do})
}

func (l *fakeLab) advance() {
	for {
		sort.SliceStable(l.pending, func(i, j int) bool { return l.pending[i].at.Before(l.pending[j].at) })
		if len(l.pending) == 0 || l.pending[0].at.After(l.clk.now) {
			return
		}
		e := l.pending[0]
		l.pending = l.pending[1:]
		e.do()
	}
}

func (l *fakeLab) takeover(j int) {
	if l.holder == -1 && l.in[j].running && l.in[j].session {
		l.holder = j
	}
}

// release drops the lease held by i; the other instance takes it a
// moment later.
func (l *fakeLab) release(i int, d time.Duration) {
	if l.holder != i {
		return
	}
	l.holder = -1
	l.after(d, func() { l.takeover(1 - i) })
}

func (l *fakeLab) wants(i int) bool {
	in := l.in[i]
	if !in.running || !in.session || !l.probesUp {
		return false
	}
	if in.terminating && !l.termNoWithdraw {
		return false
	}
	return l.holder == i || l.both
}

func (l *fakeLab) idx(svc string) int {
	for i, in := range pair {
		if in.Svc == svc || in.Addr == svc {
			return i
		}
	}
	panic("unknown " + svc)
}

func (l *fakeLab) Edge(context.Context) (string, error) {
	l.advance()
	routes := map[string][]map[string]any{
		"198.51.100.0/24": {{"peerId": "(unspec)", "nexthops": []any{map[string]any{"ip": "0.0.0.0"}}}},
	}
	neighbors := map[string]any{}
	for i, in := range l.in {
		if in.running {
			if w := l.wants(i); w != in.advertised {
				in.advertised = w
				if in.session {
					in.updates++
				}
			}
		}
		onEdge := in.advertised && (in.session || l.keepAfterKill)
		if onEdge {
			routes["198.51.100.0/24"] = append(routes["198.51.100.0/24"], map[string]any{"peerId": pair[i].Addr})
			if i == 0 && l.unlearned {
				routes["203.0.113.0/24"] = append(routes["203.0.113.0/24"], map[string]any{"peerId": pair[i].Addr})
			}
		}
		state := "Active"
		if in.session {
			state = "Established"
		}
		gr := "advertised"
		if i == 0 && l.gr {
			gr = "advertisedAndReceived"
		}
		neighbors[pair[i].Addr] = map[string]any{
			"remoteAs": 64512, "bgpState": state, "bgpTimerHoldTimeMsecs": fakeHoldMs,
			"messageStats":         map[string]any{"updatesRecv": in.updates},
			"neighborCapabilities": map[string]any{"gracefulRestart": gr},
		}
	}
	a, _ := json.Marshal(map[string]any{"vrfId": 0, "routes": routes})
	b, _ := json.Marshal(neighbors)
	return string(a) + "\n" + string(b) + "\n", nil
}

func (l *fakeLab) Vtysh(_ context.Context, cmds ...string) error {
	l.advance()
	for _, c := range cmds {
		f := strings.Fields(c)
		if len(f) < 3 || !slices.Contains(f, "shutdown") {
			continue
		}
		if f[0] == "no" {
			i := l.idx(f[2])
			l.in[i].adminDown = false
			l.after(time.Second, func() {
				if l.in[i].running {
					l.in[i].session = true
				}
			})
			continue
		}
		i := l.idx(f[1])
		l.in[i].adminDown, l.in[i].session = true, false
		l.release(i, time.Second)
	}
	return nil
}

func (l *fakeLab) Signal(_ context.Context, svc, sig string) error {
	l.advance()
	i := l.idx(svc)
	in := l.in[i]
	switch sig {
	case sigtermSignal:
		in.terminating = true
		l.after(time.Second, func() {
			in.running, in.session, in.exitCode = false, false, l.termExit
			l.release(i, 500*time.Millisecond)
		})
	case sigkillSignal:
		in.running, in.exitCode = false, 137
		l.after(fakeHoldMs*time.Millisecond, func() {
			in.session = false
			l.release(i, time.Second)
		})
	default:
		return errors.New("unknown signal " + sig)
	}
	return nil
}

func (l *fakeLab) Wait(_ context.Context, svc string) (int, error) {
	in := l.in[l.idx(svc)]
	for in.running {
		l.clk.Sleep(100 * time.Millisecond)
		l.advance()
	}
	return in.exitCode, nil
}

func (l *fakeLab) Start(_ context.Context, svc string) error {
	l.advance()
	in := l.in[l.idx(svc)]
	*in = fakeInst{running: true, adminDown: in.adminDown, updates: in.updates}
	l.after(2*time.Second, func() {
		if !in.adminDown {
			in.session = true
		}
	})
	return nil
}

func (l *fakeLab) Probes(file string) error {
	l.probeFiles = append(l.probeFiles, file)
	up := file == probesUp
	l.after(time.Second, func() { l.probesUp = up })
	return nil
}

func (l *fakeLab) HA(_ context.Context, in instance) (HAStatus, error) {
	l.advance()
	i := l.idx(in.Svc)
	if !l.in[i].running {
		return HAStatus{}, errors.New("connection refused")
	}
	st := HAStatus{Role: "standby", Mode: "inject"}
	if l.holder == i {
		st.Role = "active"
	}
	if l.holder >= 0 {
		st.Holder = pair[l.holder].ID
	}
	return st, nil
}
