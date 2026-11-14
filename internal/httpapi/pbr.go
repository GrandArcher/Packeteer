package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/GrandArcher/Packeteer/internal/pbr"
)

// PolicyRouting is the host policy routing of the probe sources (#582), the
// same Plan, Apply and Verify as `packeteer -pbr linux -apply`. Preview
// changes nothing; Apply runs the plan whose token it is given, or none.
type PolicyRouting interface {
	Preview(ctx context.Context) (pbr.Preview, error)
	Apply(ctx context.Context, token string) (pbr.Result, error)
}

// SetPolicyRouting installs the host policy routing. It may be called after
// New, once the live config exists.
func (s *Server) SetPolicyRouting(p PolicyRouting) {
	if s == nil {
		return
	}
	s.pbr.Store(&p)
}

func (s *Server) policyRouting() PolicyRouting {
	if p := s.pbr.Load(); p != nil {
		return *p
	}
	return nil
}

// handlePolicyRouting shows the planned ip rule and ip route lines and what
// the kernel does for each provider now. It runs no changing command.
func (s *Server) handlePolicyRouting(w http.ResponseWriter, r *http.Request) {
	p := s.policyRouting()
	if p == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "host policy routing is not available on this instance"})
		return
	}
	pv, err := p.Preview(r.Context())
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, pv)
}

// handlePolicyRoutingApply runs the shown plan on the host. It needs
// "confirm": true and the token of the plan the admin saw; a plan that has
// since changed is refused with 409 and nothing runs.
func (s *Server) handlePolicyRoutingApply(w http.ResponseWriter, r *http.Request) {
	p := s.policyRouting()
	if p == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "host policy routing is not available on this instance"})
		return
	}
	if !s.writesEnabled() {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "changing the host's routing needs auth or basic auth"})
		return
	}
	var req struct {
		Confirm bool   `json:"confirm"`
		Token   string `json:"token"`
	}
	if !decodeLarge(w, r, &req, 1024) {
		return
	}
	if !req.Confirm || req.Token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "send confirm: true and the token of the plan you reviewed"})
		return
	}
	res, err := p.Apply(r.Context(), req.Token)
	switch {
	case errors.Is(err, pbr.ErrPlanChanged):
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error() + "; review the new plan", "code": "plan_changed"})
	case err != nil:
		s.log.Warn("host policy routing apply failed", "err", err)
		noteAudit(r, "pbr", "apply failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "the host's routing could not be changed (steps already run were undone unless a rollback error is listed): " + err.Error()})
	default:
		noteAudit(r, "pbr", "applied "+strconv.Itoa(res.Applied)+" commands, verified="+boolText(res.Verified))
		writeJSON(w, http.StatusOK, res)
	}
}
