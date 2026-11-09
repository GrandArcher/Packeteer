package main

import (
	"runtime/debug"
	"testing"
)

func TestTuneGC(t *testing.T) {
	prev := debug.SetGCPercent(100)
	t.Cleanup(func() { debug.SetGCPercent(prev) })

	if !tuneGC(func(string) string { return "" }) {
		t.Fatal("tuneGC with GOGC unset did not change the setting")
	}
	if got := debug.SetGCPercent(100); got != DefaultGCPercent {
		t.Fatalf("GC percent = %d, want %d", got, DefaultGCPercent)
	}

	env := func(k string) string {
		if k == "GOGC" {
			return "200"
		}
		return ""
	}
	if tuneGC(env) {
		t.Fatal("tuneGC changed the setting although GOGC is set")
	}
	if got := debug.SetGCPercent(100); got != 100 {
		t.Fatalf("GC percent = %d, want it left at 100", got)
	}
}
