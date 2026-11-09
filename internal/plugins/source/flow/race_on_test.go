//go:build race

package flow

// raceEnabled is true when tests run under -race, which slows the flow
// hot paths several times over.
const raceEnabled = true
