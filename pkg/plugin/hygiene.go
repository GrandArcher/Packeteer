package plugin

import (
	"context"
	"errors"
	"net/netip"
)

// KindRegistry is the extension point for registry hygiene (#289): a
// plugin that reads one registry (PeeringDB) and compares it with what the
// network does, and/or applies a change a person confirmed. Reads are GET
// only. A plugin never announces and never changes the learned RIB.
const KindRegistry Kind = "registry"

// RegistryCheckers is the registry for registry.sources.
var RegistryCheckers = NewRegistry[RegistryChecker](KindRegistry)

// ErrRegistryNoPush is returned by Push for a change the plugin does not
// apply.
var ErrRegistryNoPush = errors.New("registry: this change cannot be pushed here")

// Finding severities.
const (
	RegistryInfo    = "info"
	RegistryWarning = "warning"
	RegistryError   = "error"
)

// RegistryFacts is what the network observed, handed to Check. It carries
// no credentials.
type RegistryFacts struct {
	// ASNs are the origin ASNs the network owns.
	ASNs []uint32
	// Announced4 and Announced6 count, per ASN, the learned prefixes it
	// originates.
	Announced4, Announced6 map[uint32]int
	// Sessions are the exchange attachments the config describes.
	Sessions []RegistrySession
	// Headroom is the percent added to the announced counts when a
	// max-prefix value is suggested.
	Headroom int
}

// RegistrySession is one configured exchange attachment.
type RegistrySession struct {
	Exchange string
	// IXID is the PeeringDB ix id of the exchange, 0 when unknown.
	IXID int
	// Addrs are the network's own router addresses on the peering LAN
	// (exchanges[].local_lan_addrs). Empty means the connection records
	// cannot be compared.
	Addrs []netip.Addr
	// SpeedMbps is the port speed, 0 when the config does not say.
	SpeedMbps int
}

// RegistryChange is one change a person can confirm. Registry is the type
// of the registry plugin that applies it.
type RegistryChange struct {
	Registry string `json:"registry"`
	// Op is "create_object", "delete_object", or "update_field".
	Op string `json:"op"`
	// Class and Key name an IRR object ("route", "192.0.2.0/24AS64496") or
	// a PeeringDB record ("net", "42").
	Class string `json:"class"`
	Key   string `json:"key"`
	// Object is the full RPSL text for create_object and delete_object.
	Object string `json:"object,omitempty"`
	// Field, Old, and New describe update_field.
	Field string `json:"field,omitempty"`
	Old   string `json:"old,omitempty"`
	New   string `json:"new,omitempty"`
}

// RegistryFinding is one drift between the registries and the network.
type RegistryFinding struct {
	// ID is stable across scans for the same drift.
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	// Registry is the registry the drift is in: irr, rpki, as-set, or
	// peeringdb.
	Registry string `json:"registry"`
	Subject  string `json:"subject"`
	Message  string `json:"message"`
	// Diff is the exact text to submit by hand: RPSL or a field diff.
	Diff string `json:"diff,omitempty"`
	// Change is set when a plugin can apply it. Nil is suggest-only.
	Change *RegistryChange `json:"change,omitempty"`
}

// RegistryChecker reads one registry and applies confirmed changes.
type RegistryChecker interface {
	Lifecycle
	// Check compares the registry with the facts. It only reads.
	Check(ctx context.Context, f RegistryFacts) ([]RegistryFinding, error)
	// Push applies one change. It is called only after a person confirmed
	// the diff. A change the plugin does not apply returns
	// ErrRegistryNoPush.
	Push(ctx context.Context, c RegistryChange) error
}
