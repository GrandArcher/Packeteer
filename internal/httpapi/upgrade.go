package httpapi

import (
	"context"
	"errors"
	"net/http"
	"runtime"

	"github.com/GrandArcher/Packeteer/internal/upgrade"
)

// Upgrade from the UI (#196). An admin sees the running version, checks
// GitHub releases, upgrades to a chosen release, and rolls back. Nothing
// here announces. A switch is prepared (download, signature and checksum
// check, start check of the new binary against this config) while the
// controller keeps running, and only then does the controller shut down
// through the SIGTERM path, which withdraws every Packeteer route. Every
// check, upgrade, and rollback is an unsafe method, so the audit log
// records it with the signed-in user.

// UpgradeControl is the upgrade manager. *upgrade.Manager implements it.
// Nil when upgrade.enabled is off.
type UpgradeControl interface {
	Status() upgrade.Status
	Check(ctx context.Context) (upgrade.Status, error)
	Apply(ctx context.Context, req upgrade.Request) (upgrade.Result, error)
	Rollback(ctx context.Context, req upgrade.Request) (upgrade.Result, error)
}

const upgradeBodyLimit = 4096

func (s *Server) handleUpgrade(w http.ResponseWriter, _ *http.Request) {
	if s.upgrade != nil {
		writeJSON(w, http.StatusOK, s.upgrade.Status())
		return
	}
	writeJSON(w, http.StatusOK, upgrade.Status{Version: s.snapshot().Version, Install: upgrade.Install(), Arch: runtime.GOARCH, Releases: []upgrade.ReleaseInfo{}})
}

// upgradeAllowed answers a change request, or says why it is refused.
func (s *Server) upgradeAllowed(w http.ResponseWriter, r *http.Request, req *upgrade.Request) bool {
	if s.upgrade == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "upgrade is off (set upgrade.enabled: true with upgrade.public_key)"})
		return false
	}
	if !s.writesEnabled() {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "upgrade needs auth or basic auth"})
		return false
	}
	return decodeLarge(w, r, req, upgradeBodyLimit)
}

func (s *Server) handleUpgradeCheck(w http.ResponseWriter, r *http.Request) {
	var req upgrade.Request
	if !s.upgradeAllowed(w, r, &req) {
		return
	}
	noteAudit(r, "releases", "check")
	st, err := s.upgrade.Check(r.Context())
	if err != nil {
		noteAudit(r, "releases", "check: "+err.Error())
		writeUpgradeError(w, s, err)
		return
	}
	detail := "check: no newer release"
	if st.Latest != nil {
		detail = "check: newer release " + st.Latest.Tag
	}
	noteAudit(r, "releases", detail)
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleUpgradeApply(w http.ResponseWriter, r *http.Request) {
	var req upgrade.Request
	if !s.upgradeAllowed(w, r, &req) {
		return
	}
	from := s.upgrade.Status().Version
	detail := "from=" + from + " to=" + req.Tag
	if req.StandbyUpgraded {
		detail += " standby_upgraded=true"
	}
	noteAudit(r, req.Tag, "upgrade "+detail)
	res, err := s.upgrade.Apply(r.Context(), req)
	if err != nil {
		noteAudit(r, req.Tag, "upgrade "+detail+": "+err.Error())
		writeUpgradeError(w, s, err)
		return
	}
	writeJSON(w, http.StatusAccepted, res)
}

func (s *Server) handleUpgradeRollback(w http.ResponseWriter, r *http.Request) {
	var req upgrade.Request
	if !s.upgradeAllowed(w, r, &req) {
		return
	}
	st := s.upgrade.Status()
	target := ""
	if st.Rollback != nil {
		target = st.Rollback.Version
	}
	detail := "from=" + st.Version + " to=" + target
	if req.StandbyUpgraded {
		detail += " standby_upgraded=true"
	}
	noteAudit(r, target, "rollback "+detail)
	res, err := s.upgrade.Rollback(r.Context(), req)
	if err != nil {
		noteAudit(r, target, "rollback "+detail+": "+err.Error())
		writeUpgradeError(w, s, err)
		return
	}
	writeJSON(w, http.StatusAccepted, res)
}

func writeUpgradeError(w http.ResponseWriter, s *Server, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, upgrade.ErrNoConfirm), errors.Is(err, upgrade.ErrBadTag), errors.Is(err, upgrade.ErrSame):
		status = http.StatusBadRequest
	case errors.Is(err, upgrade.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, upgrade.ErrNotInstall), errors.Is(err, upgrade.ErrVerify), errors.Is(err, upgrade.ErrTrial):
		status = http.StatusUnprocessableEntity
	case errors.Is(err, upgrade.ErrHA), errors.Is(err, upgrade.ErrBusy), errors.Is(err, upgrade.ErrNoPrevious):
		status = http.StatusConflict
	case errors.Is(err, upgrade.ErrFetch):
		status = http.StatusBadGateway
	default:
		s.log.Error("upgrade", "err", err)
		writeJSON(w, status, map[string]string{"error": "the upgrade failed; nothing was changed (see the controller log)"})
		return
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
