// Command checklease waits until a lease file shows that one instance
// released it (#190). The FRR HA lab used to grep container logs once for
// "ha: lease released" after SIGTERM. The logging driver can deliver that
// line about a second after the process has written it, so a release that
// did happen failed the run (Actions run 37789070267).
//
// The standby overwrites the record on its next renewal, so the released
// flag is only in the file until then. The lab starts this before SIGTERM.
// A record that is already released when the watch arms does not count:
// the release has to happen during the watch. A release that never arrives
// exits 1 when -timeout elapses. Exit 2 is a bad invocation or a failure
// to arm the watch.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("checklease", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "lease file path")
	id := fs.String("id", "", "instance id that must release the lease")
	timeout := fs.Duration("timeout", 20*time.Second, "how long to wait after the watch is armed")
	every := fs.Duration("every", 2*time.Millisecond, "backup poll interval")
	readyPath := fs.String("ready", "", "file created once the watch is armed")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *file == "" || *id == "" || *timeout <= 0 || *every <= 0 {
		fmt.Fprintln(stderr, "usage: checklease -file PATH -id ID [-timeout 20s] [-every 2ms] [-ready PATH]")
		return 2
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The bound starts when the watch is armed, not when the process
	// starts, so copying the binary into the lab container does not eat it.
	armed := make(chan struct{})
	go func() {
		select {
		case <-armed:
		case <-ctx.Done():
			return
		}
		timer := time.NewTimer(*timeout)
		defer timer.Stop()
		select {
		case <-timer.C:
			cancel()
		case <-ctx.Done():
		}
	}()
	err := waitReleased(ctx, *file, *id, *every, func() error {
		if *readyPath != "" {
			if err := os.WriteFile(*readyPath, []byte("ready\n"), 0o644); err != nil {
				return err
			}
		}
		close(armed)
		return nil
	})
	if errors.Is(err, errNotReleased) {
		fmt.Fprintf(stderr, "checklease: lease not released by %s within %s\n", *id, *timeout)
		return 1
	}
	if err != nil {
		fmt.Fprintf(stderr, "checklease: %v\n", err)
		return 2
	}
	fmt.Fprintf(stdout, "released by %s\n", *id)
	return 0
}

// errNotReleased is returned when the watch ends without seeing a release
// by the named instance. Callers distinguish it from an arming failure.
var errNotReleased = errors.New("lease not released")

// ReleasedBy reports whether raw is a lease record released by id.
// Anything that is not that record is not a release.
func ReleasedBy(raw []byte, id string) bool {
	if id == "" || len(raw) == 0 {
		return false
	}
	var rec struct {
		ID       string `json:"id"`
		Released bool   `json:"released"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return false
	}
	return rec.Released && rec.ID == id
}

// releaseWatch is the lease-file state the lab waits on. The first sample
// is the baseline and never counts: a record that is already released
// before the watch does not satisfy a SIGTERM that has not happened yet.
// A later sample that is released by id counts, and stays counted after
// the standby overwrites the file.
type releaseWatch struct {
	id   string
	seen bool
	was  bool
	hit  bool
}

func (w *releaseWatch) observe(raw []byte, readErr error) bool {
	rel := readErr == nil && ReleasedBy(raw, w.id)
	if !w.seen {
		w.seen = true
		w.was = rel
		return false
	}
	if rel && !w.was {
		w.hit = true
	}
	w.was = rel
	return w.hit
}

// waitReleased reads path until id releases the lease during the watch,
// or ctx ends. ready runs once the baseline sample is taken and directory
// events are armed; the CLI starts -timeout there. A nil ready is fine.
func waitReleased(ctx context.Context, path, id string, every time.Duration, ready func() error) error {
	if every <= 0 {
		return errors.New("poll interval must be positive")
	}
	fd, watchErr := armWatch(filepath.Dir(path))
	if watchErr != nil {
		return fmt.Errorf("watch %s: %w", filepath.Dir(path), watchErr)
	}
	if fd >= 0 {
		defer func() { _ = closeWatch(fd) }()
	}

	w := releaseWatch{id: id}
	raw, err := os.ReadFile(path)
	w.observe(raw, err)

	if ready != nil {
		if err := ready(); err != nil {
			return err
		}
	}

	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%w by %s: %w", errNotReleased, id, err)
		}
		waitWatch(fd, every)
		raw, err = os.ReadFile(path)
		if w.observe(raw, err) {
			return nil
		}
	}
}
