package preflight

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Source gathers the facts for one run. It reads the running process and
// the network; it must not announce or change config.
type Source func(ctx context.Context) Facts

// Runner runs the checks on demand and keeps the latest report for the
// health page and the metrics.
type Runner struct {
	source Source
	store  *Store
	now    func() time.Time

	mu   sync.Mutex
	last *Report
}

// NewRunner returns a runner. store may be nil, which keeps no
// confirmations: a check that needs one stays unverified.
func NewRunner(source Source, store *Store, now func() time.Time) *Runner {
	if now == nil {
		now = time.Now
	}
	return &Runner{source: source, store: store, now: now}
}

// Run gathers the facts, evaluates every check, and keeps the report.
func (r *Runner) Run(ctx context.Context) Report {
	f := r.source(ctx)
	if r.store != nil {
		f.Confirmed = r.store.Active(f.Fingerprint)
	}
	rep := Run(f, r.now())
	r.mu.Lock()
	r.last = &rep
	r.mu.Unlock()
	return rep
}

// Latest is the report of the last run, if any.
func (r *Runner) Latest() (Report, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.last == nil {
		return Report{}, false
	}
	return *r.last, true
}

// Confirm records by's confirmation of check id and runs the checks again.
// Only a check from Confirmable can be confirmed, and not while it fails on
// evidence: a held leak cannot be confirmed away.
func (r *Runner) Confirm(ctx context.Context, id, by string) (Report, error) {
	if !slices.Contains(Confirmable(), id) {
		return Report{}, fmt.Errorf("%w: %s", ErrNotConfirmable, id)
	}
	if r.store == nil {
		return Report{}, errors.New("confirmations are not kept in this setup")
	}
	f := r.source(ctx)
	for _, res := range Run(f, r.now()).Results {
		if res.ID == id && res.Status == Fail {
			return Report{}, fmt.Errorf("%w: %s", ErrFailing, res.Detail)
		}
	}
	if err := r.store.Set(f.Fingerprint, id, Confirmation{By: by, At: r.now().UTC()}); err != nil {
		return Report{}, err
	}
	return r.Run(ctx), nil
}

// Errors from Confirm.
var (
	ErrNotConfirmable = errors.New("this check cannot be confirmed by hand")
	ErrFailing        = errors.New("this check is failing")
)

// NotReadyError is returned by Gate when a check blocks injection.
type NotReadyError struct{ Report Report }

func (e *NotReadyError) Error() string {
	return "the preflight checks have not passed (" + strings.Join(e.Report.Blocking(), ", ") + "); run them from Settings and fix what they name"
}

// Gate runs the checks and returns a *NotReadyError unless every one is
// ready. The editor calls it before it saves a config that turns inject on.
func (r *Runner) Gate(ctx context.Context) error {
	if rep := r.Run(ctx); !rep.Ready {
		return &NotReadyError{Report: rep}
	}
	return nil
}

// Store keeps administrators' confirmations. They hold for one fingerprint
// of the setup (AS, community, neighbors); changing any of them voids them,
// since the router filters were confirmed for the old values.
type Store struct {
	path string

	mu          sync.Mutex
	fingerprint string
	confirmed   map[string]Confirmation
}

type storeFile struct {
	Fingerprint string                  `json:"fingerprint"`
	Confirmed   map[string]Confirmation `json:"confirmed"`
}

// OpenStore reads path. A missing file is an empty store. An empty path
// keeps confirmations in memory only.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, confirmed: map[string]Confirmation{}}
	if path == "" {
		return s, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var f storeFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	s.fingerprint = f.Fingerprint
	if f.Confirmed != nil {
		s.confirmed = f.Confirmed
	}
	return s, nil
}

// Active returns the confirmations that were made for fingerprint.
func (s *Store) Active(fingerprint string) map[string]Confirmation {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]Confirmation{}
	if s.fingerprint == fingerprint {
		for k, v := range s.confirmed {
			out[k] = v
		}
	}
	return out
}

// Set records a confirmation for fingerprint, dropping any made for another.
func (s *Store) Set(fingerprint, id string, c Confirmation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := map[string]Confirmation{}
	if s.fingerprint == fingerprint {
		for k, v := range s.confirmed {
			next[k] = v
		}
	}
	next[id] = c
	if s.path != "" {
		data, err := json.Marshal(storeFile{Fingerprint: fingerprint, Confirmed: next})
		if err != nil {
			return err
		}
		if err := writeAtomic(s.path, data); err != nil {
			return err
		}
	}
	s.fingerprint, s.confirmed = fingerprint, next
	return nil
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".preflight-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(data)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(name)
		return werr
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}
