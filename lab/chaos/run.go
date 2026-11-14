package main

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// instance is one member of the HA pair in lab/docker-compose-ha.yml.
type instance struct {
	Svc  string
	Addr string
	ID   string
}

var pair = []instance{
	{Svc: "packeteer-a", Addr: "192.0.2.10", ID: "pk-a"},
	{Svc: "packeteer-b", Addr: "192.0.2.20", ID: "pk-b"},
}

func pairAddrs() []string { return []string{pair[0].Addr, pair[1].Addr} }

// Probe files for a link flap: transit-b's probe source fails, then
// comes back.
const (
	probesUp   = "lab/probes/prefer-b.yaml"
	probesDown = "lab/probes/transit-b-down.yaml"
)

// HAStatus is the part of /api/ha the run reads.
type HAStatus struct {
	Role   string `json:"role"`
	Holder string `json:"holder"`
	Mode   string `json:"mode"`
}

// Lab is what the run does to the lab. compose (main.go) drives Docker;
// the tests drive a simulated pair.
type Lab interface {
	// Edge runs edgeCommands on the edge and returns the output.
	Edge(ctx context.Context) (string, error)
	// Vtysh runs configuration commands on the edge.
	Vtysh(ctx context.Context, cmds ...string) error
	Signal(ctx context.Context, svc, sig string) error
	// Wait blocks until svc's container has exited and returns its code.
	Wait(ctx context.Context, svc string) (int, error)
	Start(ctx context.Context, svc string) error
	// Probes installs a probe file as the fixed prober's results.
	Probes(file string) error
	HA(ctx context.Context, in instance) (HAStatus, error)
}

type clock interface {
	Now() time.Time
	Sleep(time.Duration)
}

type wallClock struct{}

func (wallClock) Now() time.Time        { return time.Now() }
func (wallClock) Sleep(d time.Duration) { time.Sleep(d) }

// Bounds. killSlack follows lab/e2e-failure-matrix.sh: the hold timer
// plus a few seconds of keepalive and read jitter.
const (
	tick          = 500 * time.Millisecond
	settle        = 5 * time.Second
	baselineWait  = 3 * time.Minute
	killSlack     = 6 * time.Second
	termWithdraw  = 30 * time.Second
	linkDownHold  = 10 * time.Second
	maxReadFails  = 30
	sigtermSignal = "SIGTERM"
	sigkillSignal = "SIGKILL"
)

var errNoSample = errors.New("edge not readable")

type runner struct {
	lab     Lab
	clk     clock
	prof    Profile
	example string
	rep     *Report

	down      downTracker
	last      Sample
	state     map[string]string
	lease     map[string]HAStatus
	running   map[string]bool
	seen      map[string]int
	readFails int
}

func newRunner(lab Lab, clk clock, prof Profile, example string) *runner {
	r := &runner{lab: lab, clk: clk, prof: prof, example: example, rep: &Report{Profile: prof.Name},
		state: map[string]string{}, lease: map[string]HAStatus{}, running: map[string]bool{}, seen: map[string]int{}}
	for _, in := range pair {
		r.running[in.Svc] = true
	}
	return r
}

// run soaks for the profile's window and returns the report.
func (r *runner) run(ctx context.Context) *Report {
	r.rep.Started = r.clk.Now()
	r.violate(checkConfigs(r.prof, r.example, r.rep.Started)...)
	err := r.cycle(ctx, r.rep.Started.Add(r.prof.Duration))
	if err == nil {
		_, _, err = r.baseline(ctx)
		if err != nil {
			err = fmt.Errorf("recovery after the last fault: %w", err)
		}
	}
	if err != nil {
		r.rep.Errors = append(r.rep.Errors, err.Error())
	}
	r.rep.Ended = r.clk.Now()
	r.violate(checkConfigs(r.prof, r.example, r.rep.Ended)...)
	r.rep.finish()
	return r.rep
}

func (r *runner) cycle(ctx context.Context, end time.Time) error {
	for pass := 0; ; pass++ {
		for _, kind := range r.prof.Faults {
			if pass > 0 && !r.clk.Now().Before(end) {
				return nil
			}
			act, stb, err := r.baseline(ctx)
			if err != nil {
				return fmt.Errorf("before %s: %w", kind, err)
			}
			f := Fault{Kind: kind, Target: act.ID, At: r.clk.Now()}
			switch kind {
			case faultSessionFlap:
				err = r.sessionFlap(ctx, &f, act, stb)
			case faultLinkFlap:
				err = r.linkFlap(ctx, &f)
			case faultSIGTERM:
				err = r.sigterm(ctx, &f, act, stb)
			case faultSIGKILL:
				err = r.sigkill(ctx, &f, act, stb)
			}
			if err != nil {
				f.Error = err.Error()
			}
			r.rep.Faults = append(r.rep.Faults, f)
			if err != nil {
				return fmt.Errorf("%s on %s: %w", kind, act.ID, err)
			}
		}
	}
}

// violate records each violation once per invariant and detail; a repeat
// on a later sample only counts, so a multi-day report stays readable.
func (r *runner) violate(vs ...Violation) {
	for _, v := range vs {
		k := v.Invariant + "\x00" + v.Detail
		if i, ok := r.seen[k]; ok {
			r.rep.Violations[i].Count++
			continue
		}
		v.Count = 1
		r.seen[k] = len(r.rep.Violations)
		r.rep.Violations = append(r.rep.Violations, v)
	}
}

func (r *runner) event(kind, subject, detail string) {
	r.rep.Events = append(r.rep.Events, Event{At: r.clk.Now(), Kind: kind, Subject: subject, Detail: detail})
}

// sample reads the edge and the running instances and checks every
// invariant. errNoSample is a read that may be retried.
func (r *runner) sample(ctx context.Context) (Sample, error) {
	out, err := r.lab.Edge(ctx)
	var s Sample
	if err == nil {
		s, err = parseSample(out)
	}
	if err != nil {
		r.readFails++
		if r.readFails >= maxReadFails {
			return Sample{}, fmt.Errorf("edge unreadable %d times in a row: %w", r.readFails, err)
		}
		return Sample{}, fmt.Errorf("%w: %v", errNoSample, err)
	}
	r.readFails = 0
	s.At = r.clk.Now()
	r.rep.Samples++
	r.violate(checkSample(s, pairAddrs())...)
	r.violate(r.down.check(s, pairAddrs())...)
	for _, in := range pair {
		st := s.Peers[in.Addr].State
		if old, seen := r.state[in.Addr]; !seen || old != st {
			if !seen {
				old = "-"
			}
			r.event("session", in.ID, old+" -> "+st)
			r.state[in.Addr] = st
		}
		if !r.running[in.Svc] {
			continue
		}
		ha, err := r.lab.HA(ctx, in)
		if err != nil {
			continue
		}
		if old, seen := r.lease[in.ID]; !seen || old.Role != ha.Role || old.Holder != ha.Holder {
			r.event("lease", in.ID, fmt.Sprintf("%s, holder %q", ha.Role, ha.Holder))
		}
		r.lease[in.ID] = ha
		r.violate(checkLiveMode(r.prof, in.ID, ha.Mode, s.At)...)
	}
	r.last = s
	return s, nil
}

// waitFor samples until cond holds or within has passed.
func (r *runner) waitFor(ctx context.Context, within time.Duration, what string, cond func(Sample) bool) (Sample, error) {
	end := r.clk.Now().Add(within)
	for {
		s, err := r.sample(ctx)
		if err == nil && cond(s) {
			return s, nil
		}
		if err != nil && !errors.Is(err, errNoSample) {
			return Sample{}, err
		}
		if err := ctx.Err(); err != nil {
			return Sample{}, err
		}
		if !r.clk.Now().Before(end) {
			return Sample{}, fmt.Errorf("%s: not within %v", what, within)
		}
		r.clk.Sleep(tick)
	}
}

// stay samples for d and fails as soon as cond breaks.
func (r *runner) stay(ctx context.Context, d time.Duration, what string, cond func(Sample) bool) error {
	end := r.clk.Now().Add(d)
	for r.clk.Now().Before(end) {
		s, err := r.sample(ctx)
		if err != nil && !errors.Is(err, errNoSample) {
			return err
		}
		if err == nil && !cond(s) {
			return fmt.Errorf("%s: broke after %v", what, s.At.Sub(end.Add(-d)).Round(time.Second))
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		r.clk.Sleep(tick)
	}
	return nil
}

// activeOf returns the one instance whose routes the edge holds.
func activeOf(s Sample) (act, stb instance, ok bool) {
	a, b := s.Holds(pair[0].Addr), s.Holds(pair[1].Addr)
	switch {
	case a && !b:
		return pair[0], pair[1], true
	case b && !a:
		return pair[1], pair[0], true
	}
	return instance{}, instance{}, false
}

// baseline waits for the steady state every fault starts from: one
// instance announcing and both sessions Established.
func (r *runner) baseline(ctx context.Context) (act, stb instance, err error) {
	if err := r.stay(ctx, settle, "settle", func(Sample) bool { return true }); err != nil {
		return act, stb, err
	}
	s, err := r.waitFor(ctx, baselineWait, "one instance announcing and both sessions Established", func(s Sample) bool {
		_, _, ok := activeOf(s)
		return ok && s.Peers[pair[0].Addr].Established() && s.Peers[pair[1].Addr].Established()
	})
	if err != nil {
		return act, stb, err
	}
	act, stb, _ = activeOf(s)
	return act, stb, nil
}

func (r *runner) since(t time.Time) *int64 {
	ms := r.clk.Now().Sub(t).Milliseconds()
	return &ms
}

func bgpCommand(line string) []string {
	return []string{"configure terminal", "router bgp 64512", line, "end"}
}

// sessionFlap shuts the active instance's session on the edge: its routes
// go, the standby takes over, and the session comes back as standby.
func (r *runner) sessionFlap(ctx context.Context, f *Fault, act, stb instance) error {
	if err := r.lab.Vtysh(ctx, bgpCommand("neighbor "+act.Addr+" shutdown")...); err != nil {
		return err
	}
	if _, err := r.waitFor(ctx, 20*time.Second, act.ID+"'s routes gone after the session shutdown", func(s Sample) bool { return !s.Holds(act.Addr) }); err != nil {
		return err
	}
	f.WithdrawMs = r.since(f.At)
	if _, err := r.waitFor(ctx, time.Minute, stb.ID+" takes over", func(s Sample) bool { return s.Holds(stb.Addr) }); err != nil {
		return err
	}
	f.RestoreMs = r.since(f.At)
	if err := r.lab.Vtysh(ctx, bgpCommand("no neighbor "+act.Addr+" shutdown")...); err != nil {
		return err
	}
	if _, err := r.waitFor(ctx, time.Minute, act.ID+"'s session back", func(s Sample) bool { return s.Peers[act.Addr].Established() }); err != nil {
		return err
	}
	return r.stay(ctx, settle, act.ID+" back as standby", func(s Sample) bool { return !s.Holds(act.Addr) && s.Holds(stb.Addr) })
}

// linkFlap fails transit-b's probe source: both instances fail closed and
// nothing of Packeteer stays on the edge until it is back.
func (r *runner) linkFlap(ctx context.Context, f *Fault) error {
	none := func(s Sample) bool { return !s.Holds(pair[0].Addr) && !s.Holds(pair[1].Addr) }
	if err := r.lab.Probes(probesDown); err != nil {
		return err
	}
	if _, err := r.waitFor(ctx, 40*time.Second, "Packeteer routes gone with transit-b's probe source", none); err != nil {
		return err
	}
	f.WithdrawMs = r.since(f.At)
	if err := r.stay(ctx, linkDownHold, "no Packeteer route while transit-b is down", none); err != nil {
		return err
	}
	if err := r.lab.Probes(probesUp); err != nil {
		return err
	}
	up := r.clk.Now()
	if _, err := r.waitFor(ctx, 2*time.Minute, "a Packeteer route back with transit-b", func(s Sample) bool { return !none(s) }); err != nil {
		return err
	}
	f.RestoreMs = r.since(up)
	return nil
}

// restart waits for a signalled instance to exit, starts it, and waits
// for its session.
func (r *runner) restart(ctx context.Context, f *Fault, in instance) error {
	code, err := r.lab.Wait(ctx, in.Svc)
	if err != nil {
		return err
	}
	f.ExitCode = &code
	if err := r.lab.Start(ctx, in.Svc); err != nil {
		return err
	}
	r.running[in.Svc] = true
	_, err = r.waitFor(ctx, 90*time.Second, in.ID+"'s session after restart", func(s Sample) bool { return s.Peers[in.Addr].Established() })
	return err
}

// sigterm stops the active instance cleanly. Its routes must leave while
// its session is still Established: seen so on a sample, or shown by an
// UPDATE that arrived after the signal (the only UPDATE Packeteer sends on
// SIGTERM is the withdraw).
func (r *runner) sigterm(ctx context.Context, f *Fault, act, stb instance) error {
	before := r.last.Peers[act.Addr].UpdatesRecv
	if err := r.lab.Signal(ctx, act.Svc, sigtermSignal); err != nil {
		return err
	}
	r.running[act.Svc] = false
	var seenUp bool
	var gone time.Time
	s, err := r.waitFor(ctx, termWithdraw, act.ID+"'s routes and session gone after SIGTERM", func(s Sample) bool {
		p := s.Peers[act.Addr]
		if !s.Holds(act.Addr) && gone.IsZero() {
			gone = s.At
			seenUp = p.Established()
		}
		return !s.Holds(act.Addr) && !p.Established()
	})
	if err != nil {
		if ctx.Err() == nil {
			r.violate(Violation{At: r.clk.Now(), Invariant: invSIGTERM, Detail: err.Error()})
		}
		return err
	}
	ms := gone.Sub(f.At).Milliseconds()
	f.WithdrawMs = &ms
	up := seenUp || s.Peers[act.Addr].UpdatesRecv > before
	f.WithdrawnWhileUp = &up
	if !up {
		r.violate(Violation{At: s.At, Invariant: invSIGTERM,
			Detail: fmt.Sprintf("%s's routes left with its session: no UPDATE arrived after SIGTERM while it was Established", act.ID)})
	}
	if _, err := r.waitFor(ctx, 30*time.Second, stb.ID+" takes over after SIGTERM", func(s Sample) bool { return s.Holds(stb.Addr) }); err != nil {
		return err
	}
	f.RestoreMs = r.since(f.At)
	if err := r.restart(ctx, f, act); err != nil {
		return err
	}
	if *f.ExitCode != 0 {
		return fmt.Errorf("%s exited %d after SIGTERM, want 0", act.ID, *f.ExitCode)
	}
	return nil
}

// sigkill kills the active instance. Nothing withdraws; its routes must
// leave with the session, no later than the negotiated hold time.
func (r *runner) sigkill(ctx context.Context, f *Fault, act, stb instance) error {
	hold := time.Duration(r.last.Peers[act.Addr].HoldMs) * time.Millisecond
	if hold <= 0 {
		return fmt.Errorf("no negotiated hold time for %s", act.ID)
	}
	f.HoldMs = hold.Milliseconds()
	if err := r.lab.Signal(ctx, act.Svc, sigkillSignal); err != nil {
		return err
	}
	r.running[act.Svc] = false
	var gone time.Time
	_, err := r.waitFor(ctx, hold+killSlack, act.ID+"'s routes gone after SIGKILL", func(s Sample) bool {
		if !s.Holds(act.Addr) && gone.IsZero() {
			gone = s.At
		}
		return !s.Holds(act.Addr) && !s.Peers[act.Addr].Established()
	})
	if err != nil && ctx.Err() == nil {
		r.violate(Violation{At: r.clk.Now(), Invariant: invSIGKILL,
			Detail: fmt.Sprintf("%s's routes or session still on the edge %v after SIGKILL, hold time %v", act.ID, hold+killSlack, hold)})
	}
	if err != nil {
		return err
	}
	ms := gone.Sub(f.At).Milliseconds()
	f.WithdrawMs = &ms
	if _, err := r.waitFor(ctx, 2*time.Minute, stb.ID+" takes over after SIGKILL", func(s Sample) bool { return s.Holds(stb.Addr) }); err != nil {
		return err
	}
	f.RestoreMs = r.since(f.At)
	if err := r.restart(ctx, f, act); err != nil {
		return err
	}
	if *f.ExitCode != 137 {
		return fmt.Errorf("%s exited %d after SIGKILL, want 137", act.ID, *f.ExitCode)
	}
	return nil
}
