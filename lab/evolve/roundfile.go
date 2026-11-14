package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/replay"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// fileRound is one line of a round file: the time of a decision round and
// its input, as policy.Input marshals to JSON.
type fileRound struct {
	At    time.Time    `json:"at"`
	Input policy.Input `json:"input"`
}

// roundFile is a recorded history in text form. Each round is encoded the
// way the controller stores it, so the replay decodes it like a stored one.
type roundFile struct {
	rounds []plugin.RoundRecord
}

func loadRoundFile(path string) (*roundFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	rf := &roundFile{}
	for n := 1; ; n++ {
		var r fileRound
		if err := dec.Decode(&r); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("%s: round %d: %w", path, n, err)
		}
		if r.At.IsZero() {
			return nil, fmt.Errorf("%s: round %d has no time", path, n)
		}
		if k := len(rf.rounds); k > 0 && !r.At.After(rf.rounds[k-1].At) {
			return nil, fmt.Errorf("%s: round %d at %s is not after the round before it", path, n, r.At.Format(time.RFC3339))
		}
		enc, err := replay.Encode(r.At, r.Input)
		if err != nil {
			return nil, fmt.Errorf("%s: round %d: %w", path, n, err)
		}
		rf.rounds = append(rf.rounds, plugin.RoundRecord{At: r.At, Input: enc})
	}
	return rf, nil
}

// Rounds implements replay.Source.
func (f *roundFile) Rounds(_ context.Context, from, to time.Time, limit int) ([]plugin.RoundRecord, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("limit %d must be positive", limit)
	}
	i := sort.Search(len(f.rounds), func(i int) bool { return !f.rounds[i].At.Before(from) })
	var out []plugin.RoundRecord
	for ; i < len(f.rounds) && f.rounds[i].At.Before(to) && len(out) < limit; i++ {
		out = append(out, f.rounds[i])
	}
	return out, nil
}
