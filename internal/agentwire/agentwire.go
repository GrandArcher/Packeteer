// Package agentwire is the JSON protocol between the controller's agent
// prober and a probe agent (#230). The agent calls the controller; the
// controller never connects to an agent, so a remote site needs no
// inbound port. An agent carries no source address or tag in a task: it
// uses the ones it declares for the provider.
package agentwire

import (
	"regexp"
	"time"
)

// Paths the controller serves, over mutual TLS.
const (
	PollPath    = "/v1/agent/poll"
	ResultsPath = "/v1/agent/results"
)

// Limits both sides enforce.
const (
	// MaxCount is the most packets one task may ask for.
	MaxCount = 100
	// MaxTimeoutMS is the longest per-packet timeout one task may ask for.
	MaxTimeoutMS = 30000
	// MaxProviders is how many providers one agent may declare.
	MaxProviders = 64
	// MaxTasksPerPoll is the most tasks one poll may return.
	MaxTasksPerPoll = 64
	// MaxPollWait is the longest a controller may hold an idle poll.
	MaxPollWait = 30 * time.Second
	// MaxBody bounds a request body on both sides.
	MaxBody = 1 << 20
)

// NameRE is the shape of a site, agent, or provider name.
var NameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// PollRequest announces the agent and asks for work. The controller
// replaces what it knew about the agent with Site and Providers.
type PollRequest struct {
	Site      string   `json:"site"`
	Providers []string `json:"providers"`
	// Free is how many tasks the agent can start now.
	Free int `json:"free"`
}

// PollResponse holds the tasks handed out. It is empty when the poll
// waited out without work.
type PollResponse struct {
	Tasks []Task `json:"tasks,omitempty"`
}

// Task is one probe run toward one address through one provider.
type Task struct {
	ID        uint64 `json:"id"`
	Provider  string `json:"provider"`
	Target    string `json:"target"`
	Count     int    `json:"count"`
	TimeoutMS int64  `json:"timeout_ms"`
}

// ResultsRequest returns finished tasks.
type ResultsRequest struct {
	Results []Result `json:"results"`
}

// Result is the raw outcome of one task: packets sent and one RTT per
// reply, as plugin.ProbeResult has it.
type Result struct {
	ID     uint64  `json:"id"`
	Sent   int     `json:"sent"`
	RTTsNS []int64 `json:"rtts_ns,omitempty"`
	// Error is set when the run could not be made. SourceUnavailable
	// marks an error from an address or tag the agent cannot use.
	Error             string `json:"error,omitempty"`
	SourceUnavailable bool   `json:"source_unavailable,omitempty"`
}
