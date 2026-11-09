package main

import "runtime/debug"

// DefaultGCPercent is the collector target when GOGC is not set (#112).
// With a full table the live heap is about 2.3 GiB and the process
// allocates slowly, so at the Go default of 100 a collection cycle takes
// minutes and RSS swings across the whole gap between the live heap and
// twice it. Running the collector at 50 halves that swing. The cost is
// small here: the load job averages 0.39 cores, and a cycle is a few CPU
// seconds. A set GOGC is left alone, so an operator can still choose.
const DefaultGCPercent = 50

// tuneGC applies DefaultGCPercent unless GOGC is set. It reports whether
// it changed the setting.
func tuneGC(getenv func(string) string) bool {
	if getenv("GOGC") != "" {
		return false
	}
	debug.SetGCPercent(DefaultGCPercent)
	return true
}
