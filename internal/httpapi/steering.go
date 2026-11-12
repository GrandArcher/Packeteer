package httpapi

import (
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/GrandArcher/Packeteer/internal/pin"
)

// Operator steering controls (#558): pin a prefix to a provider, and pause
// or resume optimization. Neither announces from here. A pin is a static
// verdict Decide applies under the static rule's rails, and the announcer
// adds the community and NO_EXPORT; a pause retires every improvement.

// PinControl sets and removes prefix pins. Add checks the allowlist and
// the learned RIB view.
type PinControl interface {
	List(now time.Time) []pin.Pin
	Add(r pin.Request, now time.Time) (pin.Pin, error)
	Remove(id string) bool
}

// Pause is whether optimization is paused, by whom, and why.
type Pause struct {
	Paused bool      `json:"paused"`
	By     string    `json:"by,omitempty"`
	Reason string    `json:"reason,omitempty"`
	Since  time.Time `json:"since,omitzero"`
}

// OptimizationControl pauses and resumes the decision engine.
type OptimizationControl interface {
	State() Pause
	// Pause reports false when optimization is already paused.
	Pause(by, reason string, now time.Time) (Pause, bool)
	// Resume reports false when optimization is not paused.
	Resume() bool
}

func (s *Server) pinControl() PinControl {
	c, _ := s.pins.Load().(PinControl)
	return c
}

func (s *Server) optimizationControl() OptimizationControl {
	c, _ := s.optimization.Load().(OptimizationControl)
	return c
}

// steerWritable refuses a change while no one can sign in, so every
// change has a named, audited actor, and while the steering gate is
// closed, so a restore of the saved state never discards a change.
func (s *Server) steerWritable(w http.ResponseWriter, what string) bool {
	if !s.writesEnabled() {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": what + " requires auth (auth.enabled) or PACKETEER_HTTP_USER and PACKETEER_HTTP_PASSWORD"})
		return false
	}
	if refuse, _ := s.steerGate.Load().(func() bool); refuse != nil && refuse() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": what + " is refused: this instance is an HA standby (call the active instance) or is still restoring its saved steering state"})
		return false
	}
	return true
}

func (s *Server) handlePins(w http.ResponseWriter, _ *http.Request) {
	c := s.pinControl()
	if c == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "pins are not available"})
		return
	}
	writeJSON(w, http.StatusOK, struct {
		meta
		Writable bool      `json:"writable"`
		Pins     []pin.Pin `json:"pins"`
	}{meta: s.snapshot().meta(), Writable: s.writesEnabled(), Pins: c.List(time.Now())})
}

type pinRequest struct {
	Prefix     string   `json:"prefix"`
	Provider   string   `json:"provider"`
	MaxLossPct *float64 `json:"max_loss_pct"`
	MaxRTTMs   float64  `json:"max_rtt_ms"`
	Duration   string   `json:"duration"`
	Reason     string   `json:"reason"`
}

func (s *Server) handlePinAdd(w http.ResponseWriter, r *http.Request) {
	c := s.pinControl()
	if !s.steerWritable(w, "pinning a prefix") {
		return
	}
	if c == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "pins are not available"})
		return
	}
	var req pinRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	bad := func(msg string) { writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg}) }
	p, err := netip.ParsePrefix(req.Prefix)
	if err != nil {
		bad("prefix: " + err.Error())
		return
	}
	if req.MaxLossPct == nil {
		bad("max_loss_pct is required (0-100): the pinned path must stay at or under it")
		return
	}
	d, err := time.ParseDuration(req.Duration)
	if err != nil {
		bad("duration: " + err.Error())
		return
	}
	got, err := c.Add(pin.Request{Prefix: p, Provider: req.Provider, MaxLossPct: *req.MaxLossPct, MaxRTTMs: req.MaxRTTMs,
		Duration: d, Reason: req.Reason, By: principalFrom(r.Context()).User}, time.Now())
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, pin.ErrConflict) {
			status = http.StatusConflict
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	noteAudit(r, got.ID, "prefix="+got.Prefix.String()+" provider="+got.Provider+" expires="+got.Expires.Format(time.RFC3339))
	writeJSON(w, http.StatusCreated, got)
}

func (s *Server) handlePinRemove(w http.ResponseWriter, r *http.Request) {
	c := s.pinControl()
	if !s.steerWritable(w, "removing a pin") {
		return
	}
	if c == nil || !c.Remove(r.PathValue("id")) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no pin with that id"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleOptimization(w http.ResponseWriter, _ *http.Request) {
	c := s.optimizationControl()
	if c == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "optimization control is not available"})
		return
	}
	writeJSON(w, http.StatusOK, struct {
		meta
		Writable bool `json:"writable"`
		Pause
	}{meta: s.snapshot().meta(), Writable: s.writesEnabled(), Pause: c.State()})
}

const maxPauseReason = 200

func (s *Server) handleOptimizationPause(w http.ResponseWriter, r *http.Request) {
	c := s.optimizationControl()
	if !s.steerWritable(w, "pausing optimization") {
		return
	}
	if c == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "optimization control is not available"})
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Reason == "" || len(req.Reason) > maxPauseReason {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "reason is required, at most " + strconv.Itoa(maxPauseReason) + " bytes"})
		return
	}
	st, ok := c.Pause(principalFrom(r.Context()).User, req.Reason, time.Now())
	if !ok {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "optimization is already paused"})
		return
	}
	noteAudit(r, "", "reason="+req.Reason)
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleOptimizationResume(w http.ResponseWriter, _ *http.Request) {
	c := s.optimizationControl()
	if !s.steerWritable(w, "resuming optimization") {
		return
	}
	if c == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "optimization control is not available"})
		return
	}
	if !c.Resume() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "optimization is not paused"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
