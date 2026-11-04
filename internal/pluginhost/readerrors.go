package pluginhost

import (
	"log/slog"
	"sort"
	"time"
)

// Optional source reads whose failure is counted (#492).
const (
	ReadTrafficMix = "traffic_mix"
	ReadVolumes    = "volumes"
)

// sourceWarnEvery is the most one source's failing read is logged at warn.
// A failing source is asked every decision round and on page loads, so an
// unthrottled warning would flood the log.
const sourceWarnEvery = time.Minute

// SourceReadErrors is how many times one read of one source failed since
// start.
type SourceReadErrors struct {
	Source string
	Read   string
	Count  uint64
}

type sourceRead struct{ source, read string }

type readFailure struct {
	count uint64
	// unlogged is the failures since the last warning.
	unlogged uint64
	warned   time.Time
}

// SourceReadFailed records a failed optional read of the source instance
// named source. The input it would have given is left out of the decision,
// so the failure must not be silent: the first one is logged at warn, then
// at most one per sourceWarnEvery with the count since the last.
func (s *Set) SourceReadFailed(source, read string, err error) {
	if s == nil {
		return
	}
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	t := now()
	s.readMu.Lock()
	if s.readErrs == nil {
		s.readErrs = map[sourceRead]*readFailure{}
	}
	f := s.readErrs[sourceRead{source, read}]
	if f == nil {
		f = &readFailure{}
		s.readErrs[sourceRead{source, read}] = f
	}
	f.count++
	f.unlogged++
	var n uint64
	if f.warned.IsZero() || t.Sub(f.warned) >= sourceWarnEvery {
		n, f.unlogged, f.warned = f.unlogged, 0, t
	}
	s.readMu.Unlock()
	if n == 0 {
		return
	}
	log := s.log
	if log == nil {
		log = slog.Default()
	}
	log.Warn("source read failed; its input is left out of the decision", "source", source, "read", read, "failures", n, "err", err)
}

// SourceReadErrors is the failure count of every source read that failed
// at least once, sorted by source and read.
func (s *Set) SourceReadErrors() []SourceReadErrors {
	if s == nil {
		return nil
	}
	s.readMu.Lock()
	out := make([]SourceReadErrors, 0, len(s.readErrs))
	for k, f := range s.readErrs {
		out = append(out, SourceReadErrors{Source: k.source, Read: k.read, Count: f.count})
	}
	s.readMu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].Read < out[j].Read
	})
	return out
}
