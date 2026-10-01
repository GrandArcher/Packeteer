// Command soak is Packeteer's load and soak harness (#51). Lab only: it
// plays the edge router with an in-process GoBGP speaker holding a
// full-table-sized synthetic RIB of documentation prefixes, exports IPFIX
// at a sustained rate toward that table, withdraws and re-announces part
// of it continuously, and reads the Packeteer process (/proc) and its ops
// API while that runs. It then stops Packeteer and compares what it
// measured with the budgets in lab/soak/budgets.yaml. Any budget over, or
// any broken invariant (session or readiness lost, a route sent by
// observe mode, an unclean stop), exits 1.
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
	"os"
	"os/exec"
	"os/signal"
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

func commonFlags(fs *flag.FlagSet) (budgets, profile *string, pt *ports) {
	budgets = fs.String("budgets", "lab/soak/budgets.yaml", "budget file")
	profile = fs.String("profile", "pr", "profile name in the budget file")
	pt = &ports{}
	fs.IntVar(&pt.BGP, "bgp-port", 11179, "router port on 127.0.0.1")
	fs.IntVar(&pt.Flow, "flow-port", 12055, "Packeteer IPFIX port on 127.0.0.1")
	fs.IntVar(&pt.HTTP, "http-port", 18081, "Packeteer ops API port on 127.0.0.1")
	return
}

func cmdConfig(args []string) error {
	fs := flag.NewFlagSet("config", flag.ExitOnError)
	budgets, profile, pt := commonFlags(fs)
	out := fs.String("out", "", "write the Packeteer config here (default stdout)")
	data := fs.String("data", "/var/lib/packeteer", "storage directory as Packeteer sees it")
	_ = fs.Parse(args)
	p, err := loadProfile(*budgets, *profile)
	if err != nil {
		return err
	}
	cfg := packeteerConfig(p, *pt, *data)
	if *out == "" {
		_, err = os.Stdout.WriteString(cfg)
		return err
	}
	return os.WriteFile(*out, []byte(cfg), 0o644)
}

type runOpts struct {
	name     string
	prof     Profile
	pt       ports
	pid      int
	stop     string
	procRoot string
	snmp     string
}

func cmdRun(args []string) (bool, error) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	budgets, profile, pt := commonFlags(fs)
	pid := fs.Int("pid", 0, "Packeteer's PID as the host sees it")
	stop := fs.String("stop", "", "shell command that stops Packeteer with SIGTERM (default: signal -pid)")
	duration := fs.Duration("duration", 0, "override the profile's soak duration")
	jsonOut := fs.String("json", "", "write the result as JSON here")
	procRoot := fs.String("proc", "/proc", "procfs root")
	_ = fs.Parse(args)
	p, err := loadProfile(*budgets, *profile)
	if err != nil {
		return false, err
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
	o := runOpts{name: *profile, prof: p, pt: *pt, pid: *pid, stop: *stop, procRoot: *procRoot, snmp: *procRoot + "/net/snmp"}
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
	r := Result{Profile: o.name, Prefixes: p.Prefixes, Failures: []string{}}
	fail := func(format string, a ...any) {
		msg := fmt.Sprintf(format, a...)
		log.Print("FAIL: ", msg)
		r.Failures = append(r.Failures, msg)
	}
	papi := newAPI(fmt.Sprintf("http://127.0.0.1:%d", o.pt.HTTP))
	readP := func() (proc, error) { return readProc(o.procRoot, o.pid) }

	rt, err := startRouter(ctx, o.pt.BGP, tbl)
	if err != nil {
		return r, err
	}
	defer rt.stop()

	if !waitFor(ctx, 2*time.Minute, func() bool { _, _, err := papi.metrics(ctx); return err == nil }) {
		return r, errors.New("Packeteer ops API did not come up")
	}
	if _, err := readP(); err != nil {
		return r, fmt.Errorf("read Packeteer process %d: %w", o.pid, err)
	}
	if ov, _, err := papi.overview(ctx); err != nil || ov.Mode != "observe" {
		return r, fmt.Errorf("Packeteer must run in observe mode (got %q, %v)", ov.Mode, err)
	}

	// Learn: Packeteer connects and the session opens with a full-table
	// dump, as on a real edge.
	actx, acancel := context.WithTimeout(ctx, 2*time.Minute)
	err = rt.accept(actx)
	acancel()
	if err != nil {
		return r, err
	}
	before, _ := readP()
	t0 := time.Now()
	log.Printf("session up; sending %d prefixes (/%d IPv6)", p.Prefixes, tbl.v6Bits)
	if err := rt.load(ctx, 0, p.Prefixes); err != nil {
		return r, err
	}
	if err := rt.endOfRIB(); err != nil {
		return r, err
	}
	log.Printf("table sent in %s", time.Since(t0).Round(time.Millisecond))
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

	// Soak: flows, churn, and sampling.
	udp0, udpErr := readUDP(o.snmp)
	cpu0, _ := readP()
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
	go func() { churnDone <- churn(soakCtx, rt, tbl, p.Churn, &r.ChurnUpdates, fail) }()

	soakStart := time.Now()
	var warmRSS, postRSS, lat []float64
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
		// Warmup is the baseline. Samples after it are the growth window.
		if el < p.Warmup {
			warmRSS = append(warmRSS, sample)
		} else {
			postRSS = append(postRSS, sample)
		}
		m, d1, err1 := papi.metrics(ctx)
		_, d2, err2 := papi.overview(ctx)
		if err1 != nil || err2 != nil {
			sampleErrs++
			log.Printf("api: %v %v", err1, err2)
		} else {
			lat = append(lat, float64(d1.Milliseconds()), float64(d2.Milliseconds()))
			if !m.Ready {
				notReady++
			}
			if !m.SessionUp {
				sessionDown++
			}
		}
		log.Printf("t=%s rss=%.0fMiB cpu=%.1fs threads=%d rib=%d flows=%d",
			el.Round(time.Second), float64(pr.RSS)/(1<<20), pr.CPU, pr.Threads, m.RIBPrefixes, exp.sent.Load())
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
	soakEnd := time.Now()
	r.DurationSeconds = soakEnd.Sub(soakStart).Seconds()
	r.FlowRecords = exp.sent.Load()
	if ctx.Err() != nil {
		return r, ctx.Err()
	}
	cpu1, err := readP()
	if err != nil {
		return r, fmt.Errorf("Packeteer process gone after soak: %w", err)
	}
	r.CPUAvgCores = (cpu1.CPU - cpu0.CPU) / r.DurationSeconds
	r.RSSPeakMB = float64(cpu1.HWM) / (1 << 20)
	r.RSSBaselineMB, r.RSSEndMB = growth(warmRSS, postRSS)
	r.RSSGrowthMB = max(0, r.RSSEndMB-r.RSSBaselineMB)
	r.APIP99Ms = percentile(lat, 99)
	if udp1, err := readUDP(o.snmp); err == nil && udpErr == nil && p.FlowRate > 0 {
		in, drop := udp1.In-udp0.In, udp1.RcvbufErrors-udp0.RcvbufErrors
		if in+drop > 0 {
			r.UDPDropPct = 100 * float64(drop) / float64(in+drop)
		}
	}
	if notReady > 0 {
		fail("packeteer_ready was 0 in %d samples during the soak", notReady)
	}
	if sessionDown > 0 {
		fail("the iBGP session was down in %d samples during the soak", sessionDown)
	}
	if sampleErrs > len(lat)/20 {
		fail("%d API samples failed", sampleErrs)
	}

	// Reconverge: the last churned batch comes back and the view is whole.
	t1 := time.Now()
	if pending >= 0 {
		if err := rt.load(ctx, pending, min(pending+churnBatch(p.Churn), p.Prefixes)); err != nil {
			return r, err
		}
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

	// Observe announces nothing, under any load.
	r.PacketeerRoutes = rt.adjIn(ctx)
	if r.PacketeerRoutes != 0 {
		fail("observe mode sent %d routes to the router", r.PacketeerRoutes)
	}

	// Stop: SIGTERM, a clean exit, and the session closes.
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
	if !waitFor(ctx, 15*time.Second, func() bool { return !rt.established(ctx) }) {
		fail("router session still established after Packeteer stopped")
	}
	return r, nil
}

// churnBatch is the prefixes withdrawn per second for churn per minute.
func churnBatch(perMinute int) int {
	if perMinute <= 0 {
		return 0
	}
	return max(1, perMinute/60)
}

// churn withdraws one batch of IPv6 entries a second and announces the
// previous batch again, walking the table. It returns the first entry of
// the batch still withdrawn when ctx ends, or -1.
func churn(ctx context.Context, rt *router, tbl table, perMinute int, updates *uint64, fail func(string, ...any)) int {
	b := churnBatch(perMinute)
	if b == 0 {
		return -1
	}
	span := tbl.n - v4Count
	off, pending := 0, -1
	t := time.NewTicker(time.Second)
	defer t.Stop()
	bg := context.Background() // finish a batch after ctx ends
	for {
		select {
		case <-ctx.Done():
			return pending
		case <-t.C:
		}
		from := v4Count + off
		to := min(from+b, tbl.n)
		if err := rt.withdraw(bg, from, to); err != nil {
			fail("churn withdraw: %v", err)
			return pending
		}
		if pending >= 0 {
			if err := rt.load(bg, pending, min(pending+b, tbl.n)); err != nil {
				fail("churn announce: %v", err)
				return from
			}
		}
		*updates += uint64(2 * (to - from))
		pending = from
		off = (off + b) % max(1, span-b)
	}
}
