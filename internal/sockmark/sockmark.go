// Package sockmark tags probe sockets with a Linux fwmark and a DSCP value
// so many providers can share one source_ip and still leave through
// different paths (#157). The host's policy routing (or a router in front
// of it) matches the tag; see docs/policy-routing.md.
package sockmark

import (
	"context"
	"errors"
	"fmt"
	"syscall"
)

// ErrTag wraps every failure to tag a socket. A prober maps it to
// plugin.ErrSourceUnavailable so the provider fails closed instead of
// being measured untagged, which would measure the wrong path.
var ErrTag = errors.New("probe socket tag failed")

// MaxDSCP is the largest DSCP value (6 bits).
const MaxDSCP = 63

// Marking is the tag on a provider's probe packets. The zero value tags
// nothing.
type Marking struct {
	// Mark is the SO_MARK fwmark. It needs CAP_NET_ADMIN.
	Mark uint32
	// DSCP is the differentiated services code point in the IP header.
	DSCP uint8
}

// IsZero reports whether the marking tags nothing.
func (m Marking) IsZero() bool { return m == Marking{} }

type ctxKey struct{}

// WithContext returns a context that carries m for the traceroute paths,
// whose interfaces take only a source address.
func WithContext(ctx context.Context, m Marking) context.Context {
	if m.IsZero() {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, m)
}

// FromContext returns the marking set by WithContext, or the zero value.
func FromContext(ctx context.Context) Marking {
	m, _ := ctx.Value(ctxKey{}).(Marking)
	return m
}

// Control returns a net.Dialer or net.ListenConfig Control function that
// applies m to the socket before it connects or binds. It returns nil
// when m tags nothing.
func Control(m Marking) func(network, address string, c syscall.RawConn) error {
	if m.IsZero() {
		return nil
	}
	return func(network, _ string, c syscall.RawConn) error {
		return ApplyConn(c, network[len(network)-1] == '6', m)
	}
}

// ApplyConn applies m to the socket behind c. v6 selects the IPv6 traffic
// class option for the DSCP.
func ApplyConn(c syscall.RawConn, v6 bool, m Marking) error {
	if m.IsZero() {
		return nil
	}
	var serr error
	if err := c.Control(func(fd uintptr) { serr = Apply(int(fd), v6, m) }); err != nil {
		return fmt.Errorf("%w: %v", ErrTag, err)
	}
	return serr
}
