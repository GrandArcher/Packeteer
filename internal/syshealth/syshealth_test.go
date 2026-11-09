package syshealth

import (
	"errors"
	"testing"
	"time"
)

func TestTrackerSinceMovesOnlyWhenStateFlips(t *testing.T) {
	now := time.Date(2001, 2, 3, 4, 0, 0, 0, time.UTC)
	tr := New(func() time.Time { return now })
	if _, ok := tr.Get("n"); ok {
		t.Fatal("unseen key has an outcome")
	}
	tr.Record("n", nil)
	start := now
	now = now.Add(time.Minute)
	tr.Record("n", nil)
	o, _ := tr.Get("n")
	if !o.OK || !o.Since.Equal(start) || !o.At.Equal(now) {
		t.Fatalf("ok outcome = %+v, want since %v at %v", o, start, now)
	}
	failedAt := now.Add(time.Minute)
	now = failedAt
	tr.Record("n", errors.New("dial refused"))
	now = now.Add(time.Minute)
	tr.Record("n", errors.New("dial refused again"))
	o, _ = tr.Get("n")
	if o.OK || !o.Since.Equal(failedAt) || o.Err != "dial refused again" {
		t.Fatalf("failed outcome = %+v, want since %v", o, failedAt)
	}
	now = now.Add(time.Minute)
	tr.Record("n", nil)
	o, _ = tr.Get("n")
	if !o.OK || o.Err != "" || !o.Since.Equal(now) {
		t.Fatalf("recovered outcome = %+v", o)
	}
}

func TestTrackerUnder(t *testing.T) {
	tr := New(nil)
	tr.Record("rib/bmp/192.0.2.1", nil)
	tr.Record("rib/bmp/192.0.2.2", errors.New("closed"))
	tr.Record("rib/other/192.0.2.3", nil)
	got := tr.Under("rib/bmp/")
	if len(got) != 2 || !got["192.0.2.1"].OK || got["192.0.2.2"].OK {
		t.Fatalf("Under = %+v", got)
	}
}

func TestNilTrackerIsInert(t *testing.T) {
	var tr *Tracker
	tr.Record("x", errors.New("boom"))
	if _, ok := tr.Get("x"); ok {
		t.Fatal("nil tracker kept a result")
	}
	if len(tr.Under("")) != 0 {
		t.Fatal("nil tracker listed results")
	}
}
