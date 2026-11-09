package pluginhost

import (
	"bytes"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"
)

// A failing source read is counted every time and logged at warn at most
// once per sourceWarnEvery per source and read, with the failures since
// the last warning (#492).
func TestSourceReadFailedCountsAndThrottlesWarnings(t *testing.T) {
	var logs bytes.Buffer
	clock := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	s := &Set{log: slog.New(slog.NewTextHandler(&logs, nil)), now: func() time.Time { return clock }}
	down := errors.New("flow window unavailable")
	for range 5 {
		s.SourceReadFailed("flow", ReadVolumes, down)
	}
	s.SourceReadFailed("flow", ReadTrafficMix, down)
	s.SourceReadFailed("aggregate", ReadVolumes, down)
	if n := strings.Count(logs.String(), "source read failed"); n != 3 {
		t.Fatalf("%d warnings in the first minute, want one per source and read:\n%s", n, logs.String())
	}
	clock = clock.Add(sourceWarnEvery)
	logs.Reset()
	s.SourceReadFailed("flow", ReadVolumes, down)
	if !strings.Contains(logs.String(), "source=flow read=volumes failures=5") {
		t.Fatalf("warning after a minute must carry the failures since the last one:\n%s", logs.String())
	}
	want := []SourceReadErrors{
		{Source: "aggregate", Read: ReadVolumes, Count: 1},
		{Source: "flow", Read: ReadTrafficMix, Count: 1},
		{Source: "flow", Read: ReadVolumes, Count: 6},
	}
	if got := s.SourceReadErrors(); !slices.Equal(got, want) {
		t.Fatalf("SourceReadErrors = %+v, want %+v", got, want)
	}
	var nilSet *Set
	nilSet.SourceReadFailed("flow", ReadVolumes, down)
	if nilSet.SourceReadErrors() != nil {
		t.Fatal("a nil set reports errors")
	}
}
