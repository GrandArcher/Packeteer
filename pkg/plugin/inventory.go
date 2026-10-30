package plugin

import "context"

// KindInventory is the read-only source of truth for providers (#208). It
// is read by `packeteer config plan`, `diff`, and `apply` only: it is not a
// RIB source, not an input to Decide, and it never announces.
const KindInventory Kind = "inventory"

// Inventories is the registry for the inventory block.
var Inventories = NewRegistry[Inventory](KindInventory)

// Inventory reads provider data from a system of record. Fetch is one
// request series, with GET only, and returns what the system holds now.
type Inventory interface {
	Fetch(ctx context.Context) (InventoryResult, error)
}

// InventoryResult is one read. Providers are sorted by name and unique.
type InventoryResult struct {
	Providers []InventoryProvider
	// Skipped are records that carried a bad value. They are reported by the
	// plan and never written.
	Skipped []InventorySkip
}

// InventoryProvider is the part of a provider the inventory owns. An empty
// field is not managed: the config keeps its value for it.
type InventoryProvider struct {
	Name        string
	ASN         uint32
	Type        string
	SourceIP    string
	NextHop     string
	Communities []string
}

// InventorySkip names a record that was left out and why.
type InventorySkip struct {
	Name   string
	Reason string
}
