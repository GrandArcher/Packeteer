package probe

// PathMismatchReason is the provider status reason when a probe packet
// from the provider's source_ip did not leave through its next_hop
// (#150). The provider is failed closed until a later check matches.
const PathMismatchReason = "probe path mismatch"

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
