package probe

// PathMismatchReason is the provider status reason when a probe packet
// from the provider's source_ip did not leave through its next_hop
// (#150). The provider is failed closed until a later check matches.
const PathMismatchReason = "probe path mismatch"

// SourceMissingReason is the provider status reason when the path check
// found the provider's source_ip is not an address of this host (#581).
// The probes themselves may not have run yet, so the check says it.
const SourceMissingReason = "probe source address is not configured on this host"

// SetPathMismatch records the outcome of one provider's probe-path check
// (#150). A mismatch marks the provider down with reason
// PathMismatchReason; a match clears it. An unknown name is ignored. The
// mark is kept across probe rounds, so a round that stores a good
// measurement does not clear a mis-routed source. A probe source that
// cannot be bound is the more specific reason and is not overridden.
func (e *Engine) SetPathMismatch(name string, mismatch bool) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.status[name]; !ok {
		return
	}
	if mismatch {
		e.pathDown[name] = PathMismatchReason
	} else {
		delete(e.pathDown, name)
	}
	e.refreshStatusLocked(name, e.opt.Now())
}

// SetSourceMissing marks a provider down with reason SourceMissingReason
// because its source_ip cannot be bound on this host, the same finding the
// preflight egress check reports (#581). A later SetPathMismatch from a
// check that could bind the source replaces the mark. An unknown name is
// ignored.
func (e *Engine) SetSourceMissing(name string) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.status[name]; !ok {
		return
	}
	e.pathDown[name] = SourceMissingReason
	e.refreshStatusLocked(name, e.opt.Now())
}
