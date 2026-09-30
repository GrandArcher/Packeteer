package lease

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const (
	testTTL   = time.Second
	testRenew = 100 * time.Millisecond
	testHold  = 300 * time.Millisecond
	// testWait is how long a standby waits out a live holder's record.
	testWait = testTTL/2 + testHold + testRenew
)

// node is one lease instance with a switchable candidacy.
type node struct {
	*Lease
	eligible atomic.Bool
	changes  atomic.Int32
}

func newNode(t *testing.T, path, id string) *node {
	t.Helper()
	l, err := newLease(Config{Path: path, ID: id, TTL: testTTL, Renew: testRenew}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// fsync is not under test, and a slow shared CI disk would make
	// renewals miss the short test ttl.
	l.noSync = true
	n := &node{Lease: l}
	n.eligible.Store(true)
	l.SetCandidate(func() plugin.Candidacy {
		return plugin.Candidacy{Eligible: n.eligible.Load(), RouteHold: testHold}
	})
	l.OnChange(func() { n.changes.Add(1) })
	return n
}

func (n *node) start(t *testing.T) {
	t.Helper()
	if err := n.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = n.Stop(context.Background()) })
}

func waitFor(t *testing.T, what string, d time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// watchExclusive fails the test if both nodes are ever active at once.
func watchExclusive(t *testing.T, a, b *node) (stop func()) {
	t.Helper()
	done := make(chan struct{})
	var wg sync.WaitGroup
	var both atomic.Bool
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			if a.Active() && b.Active() {
				both.Store(true)
			}
			time.Sleep(time.Millisecond)
		}
	}()
	return func() {
		close(done)
		wg.Wait()
		if both.Load() {
			t.Fatal("both instances were active at the same time")
		}
	}
}

func TestConfig(t *testing.T) {
	env := plugin.Env{Getenv: func(k string) string {
		if k == IDEnv {
			return "pk-env"
		}
		return ""
	}}
	mk := func(y string) (plugin.Elector, error) {
		c, err := plugin.ConfigFromYAML(y)
		if err != nil {
			t.Fatal(err)
		}
		return New(c, env)
	}
	e, err := mk("path: /var/lib/packeteer/ha/lease.json")
	if err != nil {
		t.Fatal(err)
	}
	l := e.(*Lease)
	if l.id != "pk-env" || l.ttl != DefaultTTL || l.renew != DefaultTTL/5 {
		t.Fatalf("defaults: id=%s ttl=%s renew=%s", l.id, l.ttl, l.renew)
	}
	if e.Active() {
		t.Fatal("active before Start")
	}
	for _, bad := range []string{
		"id: a",
		"path: relative/lease.json",
		"path: /x\nid: 'bad id'",
		"path: /x\nttl: 1s",
		"path: /x\nttl: 10m",
		"path: /x\nttl: 10s\nrenew: 3s",
		"path: /x\nrenew: 10ms",
		"path: /x\nunknown: 1",
	} {
		if _, err := mk(bad); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
	if !plugin.Electors.Has(TypeName) {
		t.Fatal("lease is not registered")
	}
}

func TestOneActiveAndStandbyNeverActive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ha", "lease.json")
	a, b := newNode(t, path, "pk-a"), newNode(t, path, "pk-b")
	a.start(t)
	waitFor(t, "a active", 5*time.Second, a.Active)
	stop := watchExclusive(t, a, b)
	b.start(t)
	time.Sleep(3 * testWait / 2)
	stop()
	if b.Active() {
		t.Fatal("standby became active while the active instance renews")
	}
	st := b.Status()
	if st.Role != plugin.RoleStandby || st.Holder != "pk-a" || !strings.Contains(st.Detail, "held by pk-a") {
		t.Fatalf("standby status: %+v", st)
	}
	if st := a.Status(); st.Role != plugin.RoleActive || st.Takeovers != 1 {
		t.Fatalf("active status: %+v", st)
	}
	if a.changes.Load() == 0 {
		t.Fatal("no change notification on becoming active")
	}
}

func TestCrashTakeoverWaitsForRouteHold(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lease.json")
	a, b := newNode(t, path, "pk-a"), newNode(t, path, "pk-b")
	a.start(t)
	waitFor(t, "a active", 5*time.Second, a.Active)
	b.start(t)
	time.Sleep(3 * testRenew)
	// Crash: the renew loop stops and nothing resigns.
	a.cancel()
	a.wg.Wait()
	crashed := time.Now()
	// The dead holder's routes can live ttl/2 + hold after its last
	// renewal; the standby must not be active before then.
	minGap := testTTL/2 + testHold
	waitFor(t, "b active", 6*time.Second, b.Active)
	if gap := time.Since(crashed); gap < minGap-testRenew {
		t.Fatalf("standby took over %s after the crash, before ttl/2+route hold (%s)", gap, minGap)
	}
	if a.Active() {
		t.Fatal("crashed instance still reports active")
	}
	var rec record
	raw, _ := os.ReadFile(path)
	if err := json.Unmarshal(raw, &rec); err != nil || rec.ID != "pk-b" || rec.RouteHoldMS != testHold.Milliseconds() {
		t.Fatalf("record after takeover: %s (%v)", raw, err)
	}
}

func TestResignHandsOverAtOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lease.json")
	a, b := newNode(t, path, "pk-a"), newNode(t, path, "pk-b")
	a.start(t)
	waitFor(t, "a active", 5*time.Second, a.Active)
	b.start(t)
	time.Sleep(3 * testRenew)
	stop := watchExclusive(t, a, b)
	if err := a.Resign(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.Active() {
		t.Fatal("active after Resign")
	}
	resigned := time.Now()
	waitFor(t, "b active", 5*time.Second, b.Active)
	if d := time.Since(resigned); d > 4*testRenew {
		t.Fatalf("takeover after resign took %s", d)
	}
	// a does not grab it back.
	time.Sleep(testTTL)
	stop()
	if a.Active() || !b.Active() {
		t.Fatalf("after resign: a=%v b=%v", a.Active(), b.Active())
	}
}

// A renewal already writing when Resign runs must not make the resigner
// active again.
func TestResignDuringRenewalWriteStaysResigned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lease.json")
	a := newNode(t, path, "pk-a")
	release := make(chan struct{})
	entered := make(chan struct{})
	var armed atomic.Bool
	a.failWrite = func() error {
		if armed.CompareAndSwap(true, false) {
			close(entered)
			<-release
		}
		return nil
	}
	a.start(t)
	waitFor(t, "a active", 5*time.Second, a.Active)
	armed.Store(true)
	<-entered
	done := make(chan error, 1)
	go func() { done <- a.Resign(context.Background()) }()
	waitFor(t, "resign recorded", 5*time.Second, func() bool { return a.Status().Detail == "resigned" })
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if a.Active() {
		t.Fatal("active after Resign raced a renewal")
	}
	var rec record
	raw, _ := os.ReadFile(path)
	if err := json.Unmarshal(raw, &rec); err != nil || !rec.Released {
		t.Fatalf("record after resign: %s (%v)", raw, err)
	}
}

func TestIneligibleStepsDownAndDoesNotAcquire(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lease.json")
	a, b := newNode(t, path, "pk-a"), newNode(t, path, "pk-b")
	b.eligible.Store(false)
	a.start(t)
	b.start(t)
	waitFor(t, "a active", 5*time.Second, a.Active)
	a.eligible.Store(false)
	waitFor(t, "a standby", 5*time.Second, func() bool { return !a.Active() })
	// Nobody may take over while both are ineligible, even after the
	// lease runs out.
	time.Sleep(3 * testWait / 2)
	if b.Active() || a.Active() {
		t.Fatal("an ineligible instance became active")
	}
	b.eligible.Store(true)
	waitFor(t, "b active once eligible", 6*time.Second, b.Active)
}

func TestStepDownWhenRenewalFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lease.json")
	a := newNode(t, path, "pk-a")
	var fail atomic.Bool
	a.failWrite = func() error {
		if fail.Load() {
			return errors.New("disk gone")
		}
		return nil
	}
	a.start(t)
	waitFor(t, "a active", 5*time.Second, a.Active)
	fail.Store(true)
	failed := time.Now()
	waitFor(t, "a standby", 5*time.Second, func() bool { return !a.Active() })
	if d := time.Since(failed); d > testTTL/2+testRenew {
		t.Fatalf("stepped down %s after renewals started failing (ttl/2 is %s)", d, testTTL/2)
	}
	if st := a.Status(); st.Role != plugin.RoleStandby {
		t.Fatalf("status: %+v", st)
	}
}

func TestActiveTurnsFalseWhileLoopIsStuck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lease.json")
	a := newNode(t, path, "pk-a")
	release := make(chan struct{})
	var stuck atomic.Bool
	a.failWrite = func() error {
		if stuck.Load() {
			<-release
		}
		return nil
	}
	a.start(t)
	waitFor(t, "a active", 5*time.Second, a.Active)
	before := a.changes.Load()
	stuck.Store(true)
	waitFor(t, "a inactive while stuck", 5*time.Second, func() bool { return !a.Active() })
	waitFor(t, "a change notification", 5*time.Second, func() bool { return a.changes.Load() > before })
	close(release)
}

func TestRestartDoesNotReuseOldLease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lease.json")
	a := newNode(t, path, "pk-a")
	a.start(t)
	waitFor(t, "a active", 5*time.Second, a.Active)
	a.cancel()
	a.wg.Wait()
	// Same ID, new process: the old record is not its lease.
	a2 := newNode(t, path, "pk-a")
	a2.start(t)
	time.Sleep(testTTL / 2)
	if a2.Active() {
		t.Fatal("restarted instance took its predecessor's unexpired lease")
	}
	waitFor(t, "a2 active after the lease ran out", 6*time.Second, a2.Active)
}

func TestUnreadableRecordIsWaitedOut(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lease.json")
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := newNode(t, path, "pk-a")
	a.start(t)
	// Unknown holder: the default route hold (90s) applies.
	time.Sleep(2 * testWait)
	if a.Active() {
		t.Fatal("took an unreadable lease before the default route hold")
	}
	if st := a.Status(); !strings.Contains(st.Detail, "unknown instance") {
		t.Fatalf("status: %+v", st)
	}
	if w := a.wait(nil); w < DefaultRouteHold {
		t.Fatalf("wait for an unknown holder is %s", w)
	}
}
