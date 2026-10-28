// Package replay runs the decision engine again over stored decision rounds
// under other settings (#204). It calls policy.Decide on a state of its own
// and reads storage only; it imports no announcer, so it cannot announce,
// withdraw, or change a live decision.
package replay

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/GrandArcher/Packeteer/internal/policy"
)

// journalVersion is the format of an encoded round.
const journalVersion = 1

// maxRoundBytes caps an inflated round, so a damaged row cannot exhaust
// memory.
const maxRoundBytes = 256 << 20

// wire is policy.Input as stored. The outer Held shadows the func field of
// the embedded Input: the leak watch's holds are stored as the prefixes it
// held for this round's results.
type wire struct {
	policy.Input
	Version int            `json:"version"`
	At      time.Time      `json:"at"`
	Held    []netip.Prefix `json:"Held,omitempty"`
}

// Encode returns the stored form of the input of the decision at now:
// gzipped JSON. Synthesized sub-ranges (#122) are left out, so a replay
// never models them.
func Encode(now time.Time, in policy.Input) ([]byte, error) {
	w := wire{Input: in, Version: journalVersion, At: now.UTC()}
	w.Input.Synthesize = nil
	if in.Held != nil {
		seen := map[netip.Prefix]bool{}
		for _, r := range in.Results {
			if !seen[r.Prefix] {
				seen[r.Prefix] = true
				if in.Held(r.Prefix) {
					w.Held = append(w.Held, r.Prefix)
				}
			}
		}
	}
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		return nil, err
	}
	if err := json.NewEncoder(zw).Encode(w); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decode is the inverse of Encode. It returns the time Decide ran.
func Decode(data []byte) (time.Time, policy.Input, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return time.Time{}, policy.Input{}, err
	}
	raw, err := io.ReadAll(io.LimitReader(zr, maxRoundBytes+1))
	if err != nil {
		return time.Time{}, policy.Input{}, err
	}
	if len(raw) > maxRoundBytes {
		return time.Time{}, policy.Input{}, errors.New("round is too large")
	}
	var w wire
	if err := json.Unmarshal(raw, &w); err != nil {
		return time.Time{}, policy.Input{}, err
	}
	if w.Version != journalVersion {
		return time.Time{}, policy.Input{}, fmt.Errorf("round format %d is not supported", w.Version)
	}
	in := w.Input
	held := make(map[netip.Prefix]bool, len(w.Held))
	for _, p := range w.Held {
		held[p] = true
	}
	in.Held = func(p netip.Prefix) bool { return held[p] }
	return w.At, in, nil
}
