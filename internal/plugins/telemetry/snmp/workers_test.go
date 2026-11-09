package snmp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func multiHostYAML(n int, extra string) string {
	var b strings.Builder
	b.WriteString("interval: 30s\ntimeout: 1s\nretries: 0\n" + extra + "hosts:\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "  - name: h%d\n    address: 192.0.2.%d\n    version: 2c\n    community_env: PACKETEER_SNMP_COMMUNITY\n", i, i+1)
	}
	b.WriteString("providers:\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "  - name: p%d\n    host: h%d\n    interface: ether1\n    commit_mbps: 1000\n    billing_day: 1\n    percentile: separate\n", i, i)
	}
	return b.String()
}

func newMulti(t *testing.T, n int, extra string) *Collector {
	t.Helper()
	cfg, err := plugin.ConfigFromYAML(multiHostYAML(n, extra))
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg, plugin.Env{Logger: discardLog(), Getenv: envOf(map[string]string{"PACKETEER_SNMP_COMMUNITY": "lab-community-value"})})
	if err != nil {
		t.Fatal(err)
	}
	return p.(*Collector)
}

func TestWorkersConfig(t *testing.T) {
	if got := newMulti(t, 1, "").workers; got != 4 {
		t.Fatalf("default workers = %d, want 4", got)
	}
	if got := newMulti(t, 1, "workers: 9\n").workers; got != 9 {
		t.Fatalf("workers = %d, want 9", got)
	}
	for _, bad := range []string{"workers: 17\n", "workers: -1\n"} {
		cfg, err := plugin.ConfigFromYAML(multiHostYAML(1, bad))
		if err != nil {
			t.Fatal(err)
		}
		_, err = New(cfg, plugin.Env{Logger: discardLog(), Getenv: envOf(map[string]string{"PACKETEER_SNMP_COMMUNITY": "lab-community-value"})})
		if err == nil || !strings.Contains(err.Error(), "workers") {
			t.Fatalf("%q: err = %v", bad, err)
		}
	}
}

// Hosts are polled concurrently up to the pool size and never beyond it.
// A sequential poll never reaches three dials at once, so the gate would
// time out.
func TestPollHostsRunInParallelUpToWorkers(t *testing.T) {
	const hosts, workers = 7, 3
	c := newMulti(t, hosts, fmt.Sprintf("workers: %d\n", workers))
	var mu sync.Mutex
	inFlight, peak := 0, 0
	gate := make(chan struct{})
	var once sync.Once
	c.dial = func(_ context.Context, h hostSpec) (session, error) {
		mu.Lock()
		inFlight++
		peak = max(peak, inFlight)
		if inFlight == workers {
			once.Do(func() { close(gate) })
		}
		mu.Unlock()
		select {
		case <-gate:
		case <-time.After(5 * time.Second):
		}
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		inFlight--
		mu.Unlock()
		return nil, errors.New("down")
	}
	c.poll(t.Context(), time.Now())
	if peak != workers {
		t.Fatalf("peak concurrent hosts = %d, want %d", peak, workers)
	}
	rows, _ := c.Snapshot(t.Context())
	if len(rows) != hosts {
		t.Fatalf("rows = %d", len(rows))
	}
	for _, r := range rows {
		if r.Error != "down" {
			t.Fatalf("host %s was not polled: %+v", r.Host, r)
		}
	}
}

// One host that never answers does not hold back the others.
func TestPollSlowHostDoesNotDelayOthers(t *testing.T) {
	c := newMulti(t, 3, "workers: 2\n")
	var mu sync.Mutex
	done := map[string]bool{}
	others := make(chan struct{})
	c.dial = func(ctx context.Context, h hostSpec) (session, error) {
		if h.name == "h0" {
			select {
			case <-others:
			case <-time.After(5 * time.Second):
			}
			return nil, errors.New("slow")
		}
		mu.Lock()
		done[h.name] = true
		if len(done) == 2 {
			close(others)
		}
		mu.Unlock()
		return nil, errors.New("fast")
	}
	c.poll(t.Context(), time.Now())
	rows, _ := c.Snapshot(t.Context())
	want := []string{"slow", "fast", "fast"}
	for i, r := range rows {
		if r.Error != want[i] {
			t.Fatalf("row %d error = %q, want %q", i, r.Error, want[i])
		}
	}
}

// Cancelling while every worker is busy returns without starting the
// hosts still waiting for a slot.
func TestPollCancelStopsQueuedHosts(t *testing.T) {
	c := newMulti(t, 3, "workers: 1\n")
	ctx, cancel := context.WithCancel(t.Context())
	var mu sync.Mutex
	var dialed []string
	c.dial = func(ctx context.Context, h hostSpec) (session, error) {
		mu.Lock()
		dialed = append(dialed, h.name)
		mu.Unlock()
		cancel()
		<-ctx.Done()
		return nil, ctx.Err()
	}
	finished := make(chan struct{})
	go func() {
		c.poll(ctx, time.Now())
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("poll did not return after cancel")
	}
	if len(dialed) != 1 || dialed[0] != "h0" {
		t.Fatalf("dialed = %v, want only h0", dialed)
	}
}
