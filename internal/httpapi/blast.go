package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"

	"github.com/GrandArcher/Packeteer/internal/blast"
	"github.com/GrandArcher/Packeteer/internal/configedit"
)

// BlastControl computes the blast-radius preview (#227): what inject would
// put on the wire, from the latest decision round and the running state. A
// nil candidate previews the running config forced to inject; otherwise the
// candidate YAML is decided under its own mode. It announces nothing.
type BlastControl interface {
	Preview(candidate []byte) (blast.Report, error)
}

// SetBlast installs the preview source. It may be called after New.
func (s *Server) SetBlast(b BlastControl) {
	if s == nil {
		return
	}
	s.blast.Store(&b)
}

func (s *Server) blastControl() BlastControl {
	if b := s.blast.Load(); b != nil {
		return *b
	}
	return nil
}

// previewToken proves that a preview was made for this candidate against
// this revision of the file (base is the hash of the file the editor
// loaded). Save refuses a changed base, so a token cannot outlive its
// revision.
func (s *Server) previewToken(base string, candidate []byte) string {
	m := hmac.New(sha256.New, s.blastKey[:])
	m.Write([]byte(base))
	m.Write([]byte{0})
	m.Write([]byte(configedit.Hash(candidate)))
	return hex.EncodeToString(m.Sum(nil))
}

// handleBlast previews the running config under inject. It is read-only.
func (s *Server) handleBlast(w http.ResponseWriter, _ *http.Request) {
	b := s.blastControl()
	if b == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	rep, err := b.Preview(nil)
	if !s.blastReply(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"available": true, "report": rep})
}

// blastReply writes the error for a failed preview and reports whether
// there is a report to send.
func (s *Server) blastReply(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, blast.ErrNoRound):
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "code": "no_round"})
	default:
		s.log.Error("blast preview", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "the preview failed: " + err.Error()})
	}
	return false
}

// configGate runs the blast-radius step of PUT /api/config. It reports
// whether the save may go on. A dry run answers with the preview and the
// token and writes nothing. A change to keys that can alter announcements
// is saved only with that token, from the same revision of the file.
func (s *Server) configGate(w http.ResponseWriter, r *http.Request, req configRequest, res configedit.Result) bool {
	b := s.blastControl()
	dry := req.DryRun != nil && *req.DryRun
	switch {
	case dry && b == nil:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "the blast-radius preview is not available on this instance"})
		return false
	case dry && !res.Valid:
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": configedit.ErrInvalid.Error(), "result": res})
		return false
	case b == nil || !res.Valid:
		return true
	}
	gated := res.ReloadOnline && blast.Gated(res.Online)
	if !dry {
		if !gated || hmac.Equal([]byte(req.PreviewToken), []byte(s.previewToken(req.Base, []byte(req.YAML)))) {
			return true
		}
		writeJSON(w, http.StatusPreconditionRequired, map[string]any{"error": "this change can alter what is announced: preview it with dry_run=true, then send the preview_token with dry_run=false", "code": "preview_required", "result": res})
		return false
	}
	rep, err := b.Preview([]byte(req.YAML))
	if !s.blastReply(w, err) {
		return false
	}
	noteAudit(r, "config", fmt.Sprintf("blast preview add=%d move=%d withdraw=%d", len(rep.Add), len(rep.Move), len(rep.Withdraw)))
	body := map[string]any{"dry_run": true, "result": res, "blast": rep, "required": gated}
	if gated {
		body["preview_token"] = s.previewToken(req.Base, []byte(req.YAML))
	}
	writeJSON(w, http.StatusOK, body)
	return false
}
