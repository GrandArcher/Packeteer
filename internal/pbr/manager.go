package pbr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// ErrPlanChanged is returned by Manager.Apply when the host or the config
// differs from the plan the operator confirmed. Nothing was changed.
var ErrPlanChanged = errors.New("the host or the config changed since the plan was shown")

// Line is one planned ip command.
type Line struct {
	Command string `json:"command"`
	// Remove is true for a command that deletes something Packeteer set up
	// earlier and no provider needs now.
	Remove bool `json:"remove,omitempty"`
}

// Path is one provider's probe path as the kernel resolves it now.
type Path struct {
	Provider string `json:"provider"`
	SourceIP string `json:"source_ip"`
	NextHop  string `json:"next_hop"`
	// OK is true when a packet from SourceIP leaves through NextHop.
	OK bool `json:"ok"`
	// Detail says what the kernel answered when OK is false.
	Detail string `json:"detail,omitempty"`
}

// Preview is what applying would change. Building it changes nothing.
type Preview struct {
	Lines []Line `json:"lines"`
	Paths []Path `json:"paths"`
	// Token names this plan. Apply refuses to run unless the plan it
	// computes now has the same token, so what runs is what was shown.
	Token string `json:"token"`
}

// Result is the outcome of Apply.
type Result struct {
	Applied int    `json:"applied"`
	Paths   []Path `json:"paths"`
	// Verified is true when every provider's probes leave through its next
	// hop after the change.
	Verified bool `json:"verified"`
}

// Manager previews and applies the host's policy routing for the providers
// that Entries returns now. It is the web counterpart of `-pbr linux
// -apply`: the same Plan, Apply and Verify, so the same limits to
// Packeteer's own priorities and tables hold.
type Manager struct {
	Run     Exec
	Entries func() []Entry

	// mu keeps two applies from interleaving their ip commands.
	mu sync.Mutex
}

func token(steps []Step) string {
	h := sha256.New()
	for _, s := range steps {
		fmt.Fprintln(h, s.String())
	}
	return hex.EncodeToString(h.Sum(nil)[:12])
}

func paths(ctx context.Context, run Exec, entries []Entry) []Path {
	out := make([]Path, 0, len(entries))
	for _, e := range entries {
		p := Path{Provider: e.Name, SourceIP: e.Source.String(), NextHop: e.NextHop.String(), OK: true}
		// Verify per entry so a failure is named on its own row.
		if errs := Verify(ctx, run, []Entry{e}); len(errs) > 0 {
			p.OK = false
			p.Detail = strings.TrimPrefix(errs[0].Error(), e.Name+": ")
		}
		out = append(out, p)
	}
	return out
}

func lines(steps []Step) []Line {
	out := make([]Line, 0, len(steps))
	for _, s := range steps {
		out = append(out, Line{Command: "ip " + strings.Join(s.Args, " "), Remove: s.Remove})
	}
	return out
}

// Preview lists the ip commands apply would run and what the kernel does for
// each provider now. It runs only read commands.
func (m *Manager) Preview(ctx context.Context) (Preview, error) {
	entries := m.Entries()
	steps, err := Plan(ctx, m.Run, entries)
	if err != nil {
		return Preview{}, err
	}
	return Preview{Lines: lines(steps), Paths: paths(ctx, m.Run, entries), Token: token(steps)}, nil
}

// Apply runs the plan the operator confirmed, then checks each provider's
// path. When a step fails the steps already run are undone (see Apply in
// apply.go) and the error is returned. A plan that differs from token
// returns ErrPlanChanged before anything runs. A path that does not verify
// is reported in the Result, not as an error: the rules stay, as with the
// command line.
func (m *Manager) Apply(ctx context.Context, tok string) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entries := m.Entries()
	steps, err := Plan(ctx, m.Run, entries)
	if err != nil {
		return Result{}, err
	}
	if tok == "" || tok != token(steps) {
		return Result{}, ErrPlanChanged
	}
	if err := Apply(ctx, m.Run, steps); err != nil {
		return Result{}, err
	}
	res := Result{Applied: len(steps), Paths: paths(ctx, m.Run, entries)}
	res.Verified = true
	for _, p := range res.Paths {
		res.Verified = res.Verified && p.OK
	}
	return res, nil
}
