package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/GrandArcher/Packeteer/internal/extpolicy"
)

// applier puts a route set on the operator's daemon. An error leaves the
// previous set in place; the next poll tries again.
type applier interface {
	apply(ctx context.Context, routes []extpolicy.Route) error
}

// consumer long-polls the feed and keeps the daemon on the recommended set
// until the document's expiry, measured on this host's clock from the time
// left when it arrived. Past it, or when the feed is off, it applies the
// empty set. A change is applied as soon as the feed publishes it: when the
// daemon is also the edge Packeteer learns from, a route applied more than
// policy.NativePathConfirm after Packeteer decided it can read as the
// prefix leaving the RIB, and the improvement is retired.
type consumer struct {
	// fetch reads the document; with wait it returns once the revision
	// differs from rev or after a heartbeat.
	fetch func(ctx context.Context, rev uint64, wait bool) (extpolicy.Document, error)
	out   applier
	log   *slog.Logger
	now   func() time.Time

	applied  []extpolicy.Route
	started  bool // applied has been put on the daemon at least once
	deadline time.Time
	poll     time.Duration
	rev      uint64
	haveRev  bool
}

const (
	// startPoll is the heartbeat assumed until a document names one.
	startPoll = 5 * time.Second
	// pollSlack is how much longer than a heartbeat a long poll may take.
	pollSlack = 5 * time.Second
	// retryWait is the pause after a failed fetch.
	retryWait = time.Second
)

// step fetches once and applies what should be on the daemon now. Expired
// routes are dropped before it waits on the feed, and the wait ends at the
// expiry, so an unreachable feed is dropped on time.
func (c *consumer) step(ctx context.Context) error {
	if !c.now().Before(c.deadline) {
		c.put(ctx, nil)
	}
	limit := c.pollEvery() + pollSlack
	if left := c.deadline.Sub(c.now()); left > 0 && left < limit {
		limit = left
	}
	fctx, cancel := context.WithTimeout(ctx, limit)
	doc, err := c.fetch(fctx, c.rev, c.haveRev)
	cancel()
	now := c.now()
	want := c.applied
	switch {
	case err != nil:
		c.log.Warn("feed unreachable; keeping the routes until they expire", "err", err, "expires_in", max(c.deadline.Sub(now), 0).Round(time.Millisecond))
	case doc.ExpiresInMS <= 0:
		want, c.deadline = nil, now
	default:
		want, c.deadline = doc.Routes, now.Add(time.Duration(doc.ExpiresInMS)*time.Millisecond)
	}
	if err == nil {
		c.rev, c.haveRev = doc.Revision, true
		if doc.HeartbeatMS > 0 {
			c.poll = time.Duration(doc.HeartbeatMS) * time.Millisecond
		}
	}
	if !now.Before(c.deadline) {
		want = nil
	}
	c.put(ctx, want)
	return err
}

// put applies want unless it is already on the daemon.
func (c *consumer) put(ctx context.Context, want []extpolicy.Route) {
	if c.started && slices.EqualFunc(want, c.applied, sameOnDaemon) {
		return
	}
	if err := c.out.apply(ctx, want); err != nil {
		c.log.Error("apply", "err", err, "routes", len(want))
		return
	}
	c.log.Info("applied", "routes", len(want))
	c.applied, c.started = slices.Clone(want), true
}

func (c *consumer) pollEvery() time.Duration {
	if c.poll <= 0 {
		return startPoll
	}
	return c.poll
}

// run fetches until ctx ends, then applies the empty set. A long poll
// returns at the next change or heartbeat, so it fetches again at once;
// after a failure it pauses, waking at the expiry.
func (c *consumer) run(ctx context.Context) {
	for {
		err := c.step(ctx)
		wait := time.Duration(0)
		if err != nil {
			wait = retryWait
			if left := c.deadline.Sub(c.now()); left > 0 && left < wait {
				wait = left
			}
		}
		select {
		case <-ctx.Done():
			stop, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			c.put(stop, nil)
			cancel()
			return
		case <-time.After(wait):
		}
	}
}

// sameOnDaemon compares what a daemon is given. Provider, cause, and
// reason do not reach it, so a change in them alone is not applied again.
func sameOnDaemon(a, b extpolicy.Route) bool {
	return a.Prefix == b.Prefix && a.NextHop == b.NextHop && a.LocalPref == b.LocalPref &&
		slices.Equal(a.Communities, b.Communities) && slices.Equal(a.ASPath, b.ASPath)
}

// httpFetch reads the JSON document with the bearer token; with wait it
// long-polls for a revision other than rev.
func httpFetch(client *http.Client, url, token string) func(ctx context.Context, rev uint64, wait bool) (extpolicy.Document, error) {
	return func(ctx context.Context, rev uint64, wait bool) (extpolicy.Document, error) {
		u := strings.TrimRight(url, "/") + extpolicy.DocumentPath
		if wait {
			u += "?wait=" + strconv.FormatUint(rev, 10)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return extpolicy.Document{}, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			return extpolicy.Document{}, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return extpolicy.Document{}, fmt.Errorf("feed: %s", resp.Status)
		}
		var doc extpolicy.Document
		if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&doc); err != nil {
			return extpolicy.Document{}, fmt.Errorf("feed: %w", err)
		}
		return doc, nil
	}
}

// renderer writes the routes through a template, replacing the file in
// one rename, and runs the reload command.
type renderer struct {
	tmpl   *template.Template
	out    string
	reload []string
}

// templateFuncs are what the shipped templates use.
var templateFuncs = template.FuncMap{"split": strings.Split}

func newRenderer(tmplPath, out, reload string) (*renderer, error) {
	t, err := template.New(filepath.Base(tmplPath)).Funcs(templateFuncs).ParseFiles(tmplPath)
	if err != nil {
		return nil, err
	}
	return &renderer{tmpl: t, out: out, reload: strings.Fields(reload)}, nil
}

func (r *renderer) apply(ctx context.Context, routes []extpolicy.Route) error {
	tmp, err := os.CreateTemp(filepath.Dir(r.out), ".packeteer-policy-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	err = r.tmpl.Execute(tmp, struct{ Routes []extpolicy.Route }{routes})
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), 0o644)
	}
	if err == nil {
		err = os.Rename(tmp.Name(), r.out)
	}
	if err != nil {
		return fmt.Errorf("render %s: %w", r.out, err)
	}
	if len(r.reload) == 0 {
		return nil
	}
	if out, err := exec.CommandContext(ctx, r.reload[0], r.reload[1:]...).CombinedOutput(); err != nil {
		return fmt.Errorf("reload %q: %w: %s", strings.Join(r.reload, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// exabgp speaks the ExaBGP process API on w: it announces what is new or
// changed and withdraws what left.
type exabgp struct {
	w  io.Writer
	on map[string]extpolicy.Route
}

func (e *exabgp) apply(_ context.Context, routes []extpolicy.Route) error {
	next := make(map[string]extpolicy.Route, len(routes))
	var lines []string
	for _, r := range routes {
		key := r.Prefix.String()
		next[key] = r
		if old, ok := e.on[key]; ok && sameOnDaemon(old, r) {
			continue
		}
		lines = append(lines, exabgpAnnounce(r))
	}
	for key := range e.on {
		if _, ok := next[key]; !ok {
			lines = append(lines, "withdraw route "+key)
		}
	}
	slices.Sort(lines)
	for _, l := range lines {
		if _, err := fmt.Fprintln(e.w, l); err != nil {
			return err
		}
	}
	e.on = next
	return nil
}

func exabgpAnnounce(r extpolicy.Route) string {
	var std, large []string
	for _, c := range r.Communities {
		switch {
		case c == extpolicy.NoExport:
			std = append(std, "no-export")
		case strings.Count(c, ":") == 2:
			large = append(large, c)
		default:
			std = append(std, c)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "announce route %s next-hop %s local-preference %d", r.Prefix, r.NextHop, r.LocalPref)
	if len(r.ASPath) > 0 {
		as := make([]string, len(r.ASPath))
		for i, a := range r.ASPath {
			as[i] = fmt.Sprint(a)
		}
		fmt.Fprintf(&b, " as-path [%s]", strings.Join(as, " "))
	}
	if len(std) > 0 {
		fmt.Fprintf(&b, " community [%s]", strings.Join(std, " "))
	}
	if len(large) > 0 {
		fmt.Fprintf(&b, " large-community [%s]", strings.Join(large, " "))
	}
	return b.String()
}
