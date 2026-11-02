package extpolicy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Mirror is the announcer the outbound announce controller drives while the
// feed is configured. inner is the embedded announcer, nil when the feed is
// the only output (no announcing session). Each call goes to inner first;
// the feed records a route only once inner accepted it, so it lists exactly
// what is on the wire.
type Mirror struct {
	plugin.Base
	inner plugin.Announcer
	feed  *Feed
	// community is packeteer_community, set by Bind or BindRouters.
	community string
}

// NewMirror returns the announcer for the outbound controller.
func NewMirror(inner plugin.Announcer, feed *Feed) *Mirror {
	return &Mirror{inner: inner, feed: feed}
}

// Announce implements plugin.Announcer. Without inner, Mirror checks the
// route itself before it is published (check).
func (m *Mirror) Announce(ctx context.Context, r plugin.Route) error {
	if m.inner != nil {
		if err := m.inner.Announce(ctx, r); err != nil {
			return err
		}
	} else if err := m.check(r); err != nil {
		return err
	}
	m.feed.set(r)
	return nil
}

func (m *Mirror) check(r plugin.Route) error {
	switch {
	case m.community == "":
		return errors.New("external_policy: not bound")
	case !r.Prefix.IsValid() || r.Prefix != r.Prefix.Masked():
		return fmt.Errorf("external_policy: prefix %s is not a masked prefix", r.Prefix)
	case !r.NextHop.IsValid() || r.NextHop.Is4() != r.Prefix.Addr().Is4():
		return fmt.Errorf("external_policy: %s: next hop %s is not of the prefix's family", r.Prefix, r.NextHop)
	case r.LocalPref == 0:
		return fmt.Errorf("external_policy: %s: local_pref 0", r.Prefix)
	case !slices.Contains(r.Communities, m.community):
		return fmt.Errorf("external_policy: %s: route lacks packeteer_community %s", r.Prefix, m.community)
	}
	return nil
}

// Withdraw implements plugin.Announcer. A route inner failed to withdraw
// stays in the feed: it is still on the wire, and the controller retries.
func (m *Mirror) Withdraw(ctx context.Context, p netip.Prefix) error {
	if m.inner != nil {
		if err := m.inner.Withdraw(ctx, p); err != nil {
			return err
		}
	}
	m.feed.del(p)
	return nil
}

// WithdrawAll implements plugin.Announcer.
func (m *Mirror) WithdrawAll(ctx context.Context) error {
	if m.inner != nil {
		if err := m.inner.WithdrawAll(ctx); err != nil {
			return err
		}
	}
	m.feed.clear()
	return nil
}

// Bind binds inner to the embedded speaker. Without inner there is no
// export policy and nothing is sent on the session: it only learns.
func (m *Mirror) Bind(srv any, community string) error {
	m.community = community
	if m.inner == nil {
		return nil
	}
	b, ok := m.inner.(interface {
		Bind(any, string) error
	})
	if !ok {
		return fmt.Errorf("announce: announcer %T cannot publish on the embedded iBGP speaker", m.inner)
	}
	return b.Bind(srv, community)
}

// BindRouters implements plugin.RouterAnnouncer for inner. The feed carries
// each route once, with the provider's next hop; per-router rewrites apply
// only to the embedded session.
func (m *Mirror) BindRouters(srv any, community string, routers []plugin.RouterExport) error {
	m.community = community
	if m.inner == nil {
		return nil
	}
	r, ok := m.inner.(plugin.RouterAnnouncer)
	if !ok {
		return fmt.Errorf("announce: announcer %T cannot send per-router routes (bgp.neighbors providers/next_hops)", m.inner)
	}
	return r.BindRouters(srv, community, routers)
}

// SetRouters implements plugin.RouterReloader for inner. The controller
// forgets every route afterwards, whatever the outcome, so the feed does
// too; the next round publishes them again.
func (m *Mirror) SetRouters(ctx context.Context, routers []plugin.RouterExport) error {
	defer m.feed.clear()
	if m.inner == nil {
		return nil
	}
	r, ok := m.inner.(plugin.RouterReloader)
	if !ok {
		return fmt.Errorf("announce: announcer %T cannot replace its per-router table while running; restart instead", m.inner)
	}
	return r.SetRouters(ctx, routers)
}
