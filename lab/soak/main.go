// Command soak is Packeteer's load and soak harness (#51). Lab only: it
// plays the edge router with an in-process GoBGP speaker holding a
// full-table-sized synthetic RIB of documentation prefixes, exports IPFIX
// at a sustained rate toward that table, withdraws and re-announces part
// of it continuously, and reads the Packeteer process (/proc) and its ops
// API while that runs. It then stops Packeteer and compares what it
// measured with the budgets in lab/soak/budgets.yaml. Any budget over, or
// any broken invariant (session or readiness lost, a route sent by
// observe mode, an unclean stop), exits 1. The multi-session profiles
// (#383) play several routers and run Packeteer in inject mode; see
// multi.go.
//
//	soak config -profile pr -out /tmp/soak.yaml
//	soak run -profile pr -pid "$(docker inspect -f '{{.State.Pid}}' pksoak)" \
//	  -stop 'docker stop -t 30 pksoak' -json /tmp/soak.json
//
// lab/soak.sh runs both against the stock image with a mounted config.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

func main() {
	log.SetFlags(log.Ltime)
	log.SetPrefix("soak: ")
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "config":
		err = cmdConfig(os.Args[2:])
	case "run":
		var ok bool
		ok, err = cmdRun(os.Args[2:])
		if err == nil && !ok {
			os.Exit(1)
		}
	default:
		usage()
	}
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: soak config|run [flags]")
	os.Exit(2)
}

func commonFlags(fs *flag.FlagSet) (budgets, profile *string, multiply *int, pt *ports) {
	budgets = fs.String("budgets", "lab/soak/budgets.yaml", "budget file")
	profile = fs.String("profile", "pr", "profile name in the budget file")
	multiply = fs.Int("multiply", 0, "play the table on this many sessions, so Packeteer holds that many paths per prefix (1 to 4; default the profile's)")
	pt = &ports{}
	fs.IntVar(&pt.BGP, "bgp-port", 11179, "router port on 127.0.0.1")
	fs.IntVar(&pt.Flow, "flow-port", 12055, "Packeteer IPFIX port on 127.0.0.1")
	fs.IntVar(&pt.HTTP, "http-port", 18081, "Packeteer ops API port on 127.0.0.1")
	return
}

func cmdConfig(args []string) error {
	fs := flag.NewFlagSet("config", flag.ExitOnError)
	budgets, profile, multiply, pt := commonFlags(fs)
	out := fs.String("out", "", "write the Packeteer config here (default stdout)")
	data := fs.String("data", "/var/lib/packeteer", "storage directory as Packeteer sees it")
	mrtPath := fs.String("mrt", "", "MRT dump; a profile with simulate: true reads it to name the vip ASNs")
	_ = fs.Parse(args)
	p, err := loadProfile(*budgets, *profile)
	if err == nil {
		err = p.multiply(*multiply)
	}
	if err != nil {
		return err
	}
	if p.Simulate {
		if *mrtPath == "" {
			return errors.New("-mrt is required: a simulated profile names the vip ASNs from the dump")
		}
		if _, err := loadRealFor(&p, *mrtPath); err != nil {
			return err
		}
	}
	cfg := packeteerConfig(p, *pt, *data)
	if *out == "" {
		_, err = os.Stdout.WriteString(cfg)
		return err
	}
	return os.WriteFile(*out, []byte(cfg), 0o644)
}

// loadRealFor reads the dump for a real profile and sets the profile's table
// size, budgets, and vip ASNs from it. The log has counts only.
func loadRealFor(p *Profile, path string) (*realSet, error) {
	rt, err := loadReal(path, realOpts{peers: max(1, p.Peers), scaleTo: p.ScaleTo})
	if err != nil {
		return nil, fmt.Errorf("read the dump: %w", err)
	}
	if err := p.useReal(rt); err != nil {
		return nil, err
	}
	t := rt.info()
	log.Printf("dump: %d peers, %d played; %d IPv4 and %d IPv6 prefixes (%d added by scale_to) in %d attribute sets, %d paths, %d skipped",
		t.Peers, t.Views, t.IPv4, t.IPv6, t.Derived, t.Sets, t.Paths, t.Skipped)
	return rt, nil
}

type runOpts struct {
	name     string
	prof     Profile
	pt       ports
	real     *realSet // the dump's views when prof.Real
	pid      int
	stop     string
	procRoot string
	snmp     string
}

func cmdRun(args []string) (bool, error) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	budgets, profile, multiply, pt := commonFlags(fs)
	mrtPath := fs.String("mrt", "", "MRT TABLE_DUMP_V2 dump (gzip, bzip2 or plain) to replay; required by, and only for, a profile with real: true")
	pid := fs.Int("pid", 0, "Packeteer's PID as the host sees it")
	stop := fs.String("stop", "", "shell command that stops Packeteer with SIGTERM (default: signal -pid)")
	duration := fs.Duration("duration", 0, "override the profile's soak duration")
	jsonOut := fs.String("json", "", "write the result as JSON here")
	procRoot := fs.String("proc", "/proc", "procfs root")
	_ = fs.Parse(args)
	p, err := loadProfile(*budgets, *profile)
	if err == nil {
		err = p.multiply(*multiply)
	}
	if err != nil {
		return false, err
	}
	if p.Real != (*mrtPath != "") {
		return false, errors.New("-mrt goes with a profile that has real: true, and that profile needs it")
	}
	var rt *realSet
	if p.Real {
		if rt, err = loadRealFor(&p, *mrtPath); err != nil {
			return false, err
		}
	}
	if *duration > 0 {
		p.Duration = *duration
		if p.Warmup >= p.Duration {
			p.Warmup = p.Duration / 5
		}
	}
	if *pid <= 0 {
		return false, errors.New("-pid is required")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	o := runOpts{name: *profile, prof: p, real: rt, pt: *pt, pid: *pid, stop: *stop, procRoot: *procRoot, snmp: *procRoot + "/net/snmp"}
	r, err := run(ctx, o)
	if err != nil {
		return false, err
	}
	text, ok := report(r, p.Budgets)
	fmt.Println(text)
	if f := os.Getenv("GITHUB_STEP_SUMMARY"); f != "" {
		if fh, err := os.OpenFile(f, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644); err == nil {
			_, _ = fh.WriteString(text + "\n")
			_ = fh.Close()
		}
	}
	if *jsonOut != "" {
		b, _ := json.MarshalIndent(r, "", "  ")
		if err := os.WriteFile(*jsonOut, append(b, '\n'), 0o644); err != nil {
			return false, err
		}
	}
	return ok, nil
}

// waitFor polls cond every 200ms until it holds, ctx ends, or timeout.
func waitFor(ctx context.Context, timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return false
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func run(ctx context.Context, o runOpts) (Result, error) {
	p := o.prof
	tbl := newTable(p.Prefixes)
	if o.real != nil {
		tbl = newRealTable(o.real.views[0])
	}
	mode := "observe"
	if p.Inject > 0 {
		mode = "inject"
	}
	slow := slowID(p)
	r := Result{Profile: o.name, Prefixes: p.Prefixes, Mode: mode, Sessions: p.sessions(), Simulated: p.Simulate, Failures: []string{}}
	if o.real != nil {
		r.Table = o.real.info()
	}
	var failMu sync.Mutex
	fail := func(format string, a ...any) {
		msg := fmt.Sprintf(format, a...)
		log.Print("FAIL: ", msg)
		failMu.Lock()
		r.Failures = append(r.Failures, msg)
		failMu.Unlock()
	}
	papi := newAPI(fmt.Sprintf("http://127.0.0.1:%d", o.pt.HTTP))
	readP := func() (proc, error) { return readProc(o.procRoot, o.pid) }

	f := &fleet{adv: newAdvertised()}
	for k := range p.sessions() {
		view := tbl
		if o.real != nil {
			view = newRealTable(o.real.views[k%len(o.real.views)])
		}
		rt, err := startRouter(ctx, k, o.pt.BGP, view, f.adv)
		if err != nil {
			return r, err
		}
		defer rt.stop()
		rt.cap = p.Inject
		if k == slow {
			rt.slow = p.SlowPeerBPS
		}
		f.routers = append(f.routers, rt)
	}

	if !waitFor(ctx, 2*time.Minute, func() bool { _, _, err := papi.metrics(ctx); return err == nil }) {
		return r, errors.New("ops API did not come up")
	}
	if _, err := readP(); err != nil {
		return r, fmt.Errorf("read Packeteer process %d: %w", o.pid, err)
	}
	if ov, _, err := papi.overview(ctx); err != nil || ov.Mode != mode {
		return r, fmt.Errorf("controller must run in %s mode (got %q, %v)", mode, ov.Mode, err)
	}

	echo0, echoErr := echoesSent(o.procRoot)
	if p.Simulate && echoErr != nil {
		return r, fmt.Errorf("a simulated run checks that no ICMP echo leaves the host, and cannot read the counter: %w", echoErr)
	}

	// Learn: Packeteer connects to every router and each session opens
	// with a full-table dump, as on a real edge.
	if err := acceptAll(f, 2*time.Minute); err != nil {
		return r, err
	}
	before, _ := readP()
	t0 := time.Now()
	log.Printf("%d session(s) up; sending %d prefixes on each (%d per attribute set)", len(f.routers), p.Prefixes, tbl.setLen)
	firsts := make([]chan struct{}, len(f.routers))
	for k, rt := range f.routers {
		firsts[k] = make(chan struct{})
		go rt.serve(ctx, firsts[k])
	}
	for _, first := range firsts {
		select {
		case <-first:
		case <-ctx.Done():
			return r, ctx.Err()
		}
	}
	log.Printf("tables sent in %s", time.Since(t0).Round(time.Millisecond))
	learnTimeout := 30 * time.Minute
	if p.Budgets.LearnSeconds > 0 {
		learnTimeout = time.Duration(2*p.Budgets.LearnSeconds+60) * time.Second
	}
	var last metrics
	learned := waitFor(ctx, learnTimeout, func() bool {
		m, _, err := papi.metrics(ctx)
		if err == nil {
			last = m
		}
		return err == nil && m.RIBPrefixes >= p.Prefixes
	})
	r.LearnSeconds = time.Since(t0).Seconds()
	if !learned {
		return r, fmt.Errorf("full table not learned after %s: %d of %d prefixes", learnTimeout, last.RIBPrefixes, p.Prefixes)
	}
	after, _ := readP()
	r.LearnCPUCores = (after.CPU - before.CPU) / r.LearnSeconds
	log.Printf("learned %d prefixes in %.1fs (%.2f cores)", p.Prefixes, r.LearnSeconds, r.LearnCPUCores)

	// Soak: flows, churn, flaps, the withdraw check, and sampling.
	udp0, udpErr := readUDP(o.snmp)
	cpu0, _ := readP()
	drops0 := f.drops()
	soakCtx, stopSoak := context.WithCancel(ctx)
	exp := newExporter(tbl, p.FlowHot)
	expDone := make(chan error, 1)
	go func() {
		if p.FlowRate == 0 {
			expDone <- nil
			return
		}
		expDone <- exp.run(soakCtx, fmt.Sprintf("127.0.0.1:%d", o.pt.Flow), p.FlowRate)
	}()
	churnDone := make(chan int, 1) // first entry still withdrawn, or -1
	go func() { churnDone <- churn(soakCtx, f, tbl, p.Churn, &r.ChurnUpdates) }()
	var flaps flapStats
	var lat latencies
	var bg sync.WaitGroup
	bg.Go(func() { flapper(soakCtx, f, p.FlapEvery, slow, &flaps, fail) })
	if p.Inject > 0 {
		bg.Go(func() { withdrawCheck(soakCtx, f, tbl, slow, &lat, fail) })
	}

	soakStart := time.Now()
	var warmRSS, postRSS, allRSS, apiLat []float64
	var pace probePace
	var loops loopWatch
	notReady, sessionDown, sampleErrs := 0, 0, 0
	tick := time.NewTicker(p.Sample)
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-tick.C:
		}
		el := time.Since(soakStart)
		pr, err := readP()
		if err != nil {
			fail("Packeteer process gone during soak at %s: %v", el.Round(time.Second), err)
			break loop
		}
		r.Threads = max(r.Threads, pr.Threads)
		sample := float64(pr.RSS) / (1 << 20)
		allRSS = append(allRSS, sample)
		// Warmup is the baseline. Samples after it are the growth window.
		if el < p.Warmup {
			warmRSS = append(warmRSS, sample)
		} else {
			postRSS = append(postRSS, sample)
		}
		m, d1, err1 := papi.metrics(ctx)
		_, d2, err2 := papi.overview(ctx)
		decided, err3 := papi.decided(ctx)
		if err1 != nil || err2 != nil || err3 != nil {
			sampleErrs++
			log.Printf("api: %v %v %v", err1, err2, err3)
		} else {
			apiLat = append(apiLat, float64(d1.Milliseconds()), float64(d2.Milliseconds()))
			if !m.Ready {
				notReady++
			}
			if !m.SessionUp {
				sessionDown++
			}
			pace.sample(el, p.Warmup, m.ProbePrefixCommits, m.FlowPrefixesTracked)
			loops.sample(time.Now(), m.ProbePrefixCommits, m.MutexWaitSeconds, decided)
		}
		log.Printf("t=%s rss=%.0fMiB cpu=%.1fs threads=%d rib=%d flows=%d commits=%.0f tracked=%.0f sessions=%d",
			el.Round(time.Second), float64(pr.RSS)/(1<<20), pr.CPU, pr.Threads, m.RIBPrefixes, exp.sent.Load(),
			m.ProbePrefixCommits, m.FlowPrefixesTracked, f.up())
		if el >= p.Duration {
			break
		}
	}
	tick.Stop()
	stopSoak()
	if err := <-expDone; err != nil {
		fail("flow exporter: %v", err)
	}
	pending := <-churnDone
	bg.Wait()
	soakEnd := time.Now()
	r.DurationSeconds = soakEnd.Sub(soakStart).Seconds()
	r.FlowRecords = exp.sent.Load()
	if ctx.Err() != nil {
		return r, ctx.Err()
	}
	// One more read so the last seconds after the ticker count. Active
	// prefixes per hour are commits after warmup, scaled to an hour.
	// Passive tracked is the last flow-window estimate.
	if m, _, err := papi.metrics(ctx); err == nil {
		pace.sample(time.Since(soakStart), p.Warmup, m.ProbePrefixCommits, m.FlowPrefixesTracked)
	}
	r.ActivePerHour = pace.perHour(r.DurationSeconds, p.Warmup.Seconds())
	r.PassiveTracked = int(pace.passive)
	log.Printf("active prefixes per hour %.0f; passive tracked %d", r.ActivePerHour, r.PassiveTracked)
	cpu1, err := readP()
	if err != nil {
		return r, fmt.Errorf("controller process gone after soak: %w", err)
	}
	r.CPUAvgCores = (cpu1.CPU - cpu0.CPU) / r.DurationSeconds
	r.RSSPeakMB = float64(cpu1.HWM) / (1 << 20)
	r.RSSBaselineMB, r.RSSEndMB = growth(warmRSS, postRSS)
	r.RSSGrowthMB = max(0, r.RSSEndMB-r.RSSBaselineMB)
	r.RSSSlopeMB = riseLastThird(allRSS)
	r.APIP99Ms = percentile(apiLat, 99)
	r.DecideMaxGapSecs, r.ProbeMaxGapSecs = loops.decideGap, loops.probeGap
	r.LockWaitPerSec, r.LockWaitMaxPerSec = loops.waitRate(), loops.waitMax
	r.Flaps, r.ReconnectMaxSecs = flaps.flaps, flaps.reconnect
	r.SessionDrops = int(f.drops() - drops0)
	for _, rt := range f.routers {
		if rt.id != slow {
			r.MaxSilenceMs = max(r.MaxSilenceMs, float64(rt.silence.Load())/1e6)
		}
	}
	r.WithdrawChecks, r.SlowWithdrawLate = lat.checks, lat.slowLate
	r.WithdrawP50Ms, r.WithdrawP99Ms = percentile(lat.fast, 50), percentile(lat.fast, 99)
	r.WithdrawMaxMs, r.SlowWithdrawMaxMs = percentile(lat.fast, 100), percentile(lat.slow, 100)
	if udp1, err := readUDP(o.snmp); err == nil && udpErr == nil && p.FlowRate > 0 {
		in, drop := udp1.In-udp0.In, udp1.RcvbufErrors-udp0.RcvbufErrors
		if in+drop > 0 {
			r.UDPDropPct = 100 * float64(drop) / float64(in+drop)
		}
	}
	if p.Simulate {
		// The sim prober opens no socket, so the host's echo counter must
		// not move; a move means a real probe left the lab.
		if why := echoFault(o.procRoot, echo0); why != "" {
			fail("%s", why)
		}
	}
	if notReady > 0 {
		fail("packeteer_ready was 0 in %d samples during the soak", notReady)
	}
	if sessionDown > 0 {
		fail("no iBGP session was up in %d samples during the soak", sessionDown)
	}
	if r.SessionDrops > 0 {
		fail("%d session(s) ended during the soak without a flap", r.SessionDrops)
	}
	if sampleErrs > len(apiLat)/20 {
		fail("%d API samples failed", sampleErrs)
	}

	// Reconverge: every session is back, the last churned batch comes
	// back, and the view is whole.
	if !waitFor(ctx, reconnectWait, f.allUp) {
		fail("%d of %d sessions up %s after the soak", f.up(), len(f.routers), reconnectWait)
	}
	t1 := time.Now()
	if pending >= 0 {
		f.announce(pending, min(pending+churnBatch(p.Churn), p.Prefixes))
	}
	whole := waitFor(ctx, 5*time.Minute, func() bool {
		m, _, err := papi.metrics(ctx)
		if err == nil {
			last = m
		}
		return err == nil && m.RIBPrefixes == p.Prefixes
	})
	r.ReconvergeSecs = time.Since(t1).Seconds()
	if !whole {
		fail("RIB view has %d prefixes after churn stopped, want %d", last.RIBPrefixes, p.Prefixes)
	}
	if ov, _, err := papi.overview(ctx); err == nil {
		r.Measured = ov.Counts.Measured
	} else {
		fail("overview: %v", err)
	}

	for _, rt := range f.routers {
		r.PacketeerRoutes += int(rt.recvd.Load())
		rt.out.mu.Lock()
		r.InjectedPeak = max(r.InjectedPeak, rt.out.peak)
		if rt.out.nbad > 0 {
			fail("session %d: %d routes from Packeteer broke a rule, first: %s", rt.id, rt.out.nbad, strings.Join(rt.out.bad, "; "))
		}
		rt.out.mu.Unlock()
	}
	if p.Inject == 0 {
		// Observe announces nothing, under any load.
		if r.PacketeerRoutes != 0 {
			fail("observe mode sent %d routes to the routers", r.PacketeerRoutes)
		}
	} else {
		n, err := sameRoutes(ctx, f, slow, time.Minute)
		r.InjectedEnd = n
		if err != nil {
			fail("after the soak, %v", err)
		}
		if r.InjectedPeak == 0 {
			fail("inject mode announced nothing to the routers")
		}
		if r.WithdrawChecks == 0 {
			fail("no injected IPv4 prefix was held long enough to time a withdraw")
		}
		if p.OutageTargets > 0 {
			n, err := papi.outageIncidents(ctx)
			r.OutageEvents = n
			if err != nil || n == 0 {
				fail("the outage source raised no incident (%v)", err)
			}
		}
	}

	// Stop: SIGTERM, a clean exit, and every session closes.
	t2 := time.Now()
	if o.stop != "" {
		cmd := exec.CommandContext(ctx, "sh", "-c", o.stop)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Run(); err != nil {
			fail("stop command: %v", err)
		}
	} else if err := syscall.Kill(o.pid, syscall.SIGTERM); err != nil {
		fail("SIGTERM: %v", err)
	}
	gone := waitFor(ctx, 2*time.Minute, func() bool { _, err := readP(); return err != nil })
	r.ShutdownSeconds = time.Since(t2).Seconds()
	if !gone {
		fail("Packeteer still running %s after SIGTERM", time.Since(t2).Round(time.Second))
	}
	if !waitFor(ctx, 15*time.Second, func() bool { return !f.anyUp() }) {
		fail("a router session still established after Packeteer stopped")
	}
	for _, rt := range f.routers {
		rt.out.mu.Lock()
		if rt.id == slow {
			r.SlowAtClose = rt.out.atClose
		} else {
			r.RoutesAtClose += rt.out.atClose
		}
		rt.out.mu.Unlock()
	}
	// Packeteer withdraws while its sessions are up and only then closes
	// them. A session that reads at once has every withdraw by the Cease;
	// the slow one may not, and its routes go with the session.
	if r.RoutesAtClose > 0 {
		fail("%d Packeteer routes still on fast sessions when they closed after SIGTERM", r.RoutesAtClose)
	}
	return r, nil
}

// acceptAll waits for Packeteer to open a session to every router.
func acceptAll(f *fleet, timeout time.Duration) error {
	errs := make(chan error, len(f.routers))
	for _, rt := range f.routers {
		go func() {
			if tl, ok := rt.ln.(*net.TCPListener); ok {
				_ = tl.SetDeadline(time.Now().Add(timeout))
				defer func() { _ = tl.SetDeadline(time.Time{}) }()
			}
			errs <- rt.accept()
		}()
	}
	var all []error
	for range f.routers {
		all = append(all, <-errs)
	}
	return errors.Join(all...)
}

// churnBatch is the prefixes withdrawn per second for churn per minute.
func churnBatch(perMinute int) int {
	if perMinute <= 0 {
		return 0
	}
	return max(1, perMinute/60)
}

// churn withdraws one batch of IPv6 entries a second on every session and
// announces the previous batch again, walking the table. It returns the
// first entry of the batch still withdrawn when ctx ends, or -1.
func churn(ctx context.Context, f *fleet, tbl table, perMinute int, updates *uint64) int {
	b := churnBatch(perMinute)
	if b == 0 {
		return -1
	}
	span := tbl.n - v4Count
	off, pending := 0, -1
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return pending
		case <-t.C:
		}
		from := v4Count + off
		to := min(from+b, tbl.n)
		f.withdraw(from, to)
		if pending >= 0 {
			f.announce(pending, min(pending+b, tbl.n))
		}
		*updates += uint64(2 * (to - from))
		pending = from
		off = (off + b) % max(1, span-b)
	}
}
