package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/GrandArcher/Packeteer/internal/replay"
)

// WhatIfControl replays stored decision rounds (#204): the rounds in the
// window decided again under the running config and, when candidate YAML is
// given, under that config as well. It reads storage only and announces
// nothing. from and to are RFC 3339 times or durations ago; empty is the
// last 24 hours.
type WhatIfControl interface {
	Replay(ctx context.Context, candidate []byte, from, to string) (replay.Result, error)
}

// Errors a WhatIfControl returns for a bad request and for a replay already
// running.
var (
	ErrWhatIfInput = errors.New("invalid what-if request")
	ErrWhatIfBusy  = errors.New("another replay is running; try again when it finishes")
)

// SetWhatIf installs the replay source. It may be called after New.
func (s *Server) SetWhatIf(w WhatIfControl) {
	if s == nil {
		return
	}
	s.whatIf.Store(&w)
}

type whatIfRequest struct {
	YAML string `json:"yaml"`
	From string `json:"from"`
	To   string `json:"to"`
}

// maxWhatIfBody bounds the candidate YAML.
const maxWhatIfBody = 1 << 20

// handleWhatIf replays stored rounds. It is read-only.
func (s *Server) handleWhatIf(w http.ResponseWriter, r *http.Request) {
	p := s.whatIf.Load()
	if p == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "replay is not available: it needs a storage plugin with round_retention set"})
		return
	}
	if !s.writesEnabled() {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "a replay needs auth or basic auth"})
		return
	}
	var req whatIfRequest
	if !decodeLarge(w, r, &req, maxWhatIfBody) {
		return
	}
	res, err := (*p).Replay(r.Context(), []byte(req.YAML), req.From, req.To)
	switch {
	case err == nil:
		noteAudit(r, "whatif", "rounds="+strconv.Itoa(res.Rounds))
		writeJSON(w, http.StatusOK, res)
	case errors.Is(err, ErrWhatIfInput):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error(), "code": "invalid"})
	case errors.Is(err, ErrWhatIfBusy):
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": err.Error(), "code": "busy"})
	case errors.Is(err, context.Canceled):
		// The caller went away; there is nobody to answer and nothing failed.
	case errors.Is(err, replay.ErrNoRounds):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error(), "code": "no_rounds"})
	default:
		s.log.Error("what-if replay", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "the replay failed: " + err.Error()})
	}
}
