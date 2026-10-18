package plugin

import "time"

// KindLookup is the read-only directory (#153). It is not a RIB source
// and it never announces.
const KindLookup Kind = "lookup"

// Lookups is the registry for the lookup block.
var Lookups = NewRegistry[Lookup](KindLookup)

// Lookup serves a cached directory. View never blocks and never fetches.
// The slices it returns must not be modified. An implementation must not
// announce and must not write the RIB.
type Lookup interface {
	Lifecycle
	View() LookupView
}

// LookupView is one cached directory. Counts are zero and the network
// and membership lists are empty when the lookup is not configured, has
// not succeeded, or has gone stale. The API key is never included.
type LookupView struct {
	Configured      bool               `json:"configured"`
	Anonymous       bool               `json:"anonymous"`
	BaseURL         string             `json:"base_url,omitempty"`
	Fetched         time.Time          `json:"fetched,omitempty"`
	Stale           bool               `json:"stale"`
	Error           string             `json:"error,omitempty"`
	NetworkCount    int                `json:"network_count"`
	MembershipCount int                `json:"membership_count"`
	Exchanges       []LookupExchange   `json:"exchanges"`
	Networks        []LookupNetwork    `json:"networks"`
	Memberships     []LookupMembership `json:"memberships"`
}

// LookupExchange is one configured exchange and the ix record that matched
// it. Error is set when that ix id was not in the directory. IXFError is
// set when the optional IX-F document failed; that does not clear the
// directory rows.
type LookupExchange struct {
	Name     string `json:"name"`
	IXID     int    `json:"ix_id"`
	IXName   string `json:"ix_name,omitempty"`
	City     string `json:"city,omitempty"`
	Country  string `json:"country,omitempty"`
	IXFURL   string `json:"ixf_url,omitempty"`
	Error    string `json:"error,omitempty"`
	IXFError string `json:"ixf_error,omitempty"`
}

// LookupNetwork is one network. Name is the network name and Org the
// organization that owns it; either is empty when the directory has none.
// InfoPrefixes4 and InfoPrefixes6 are nil when the directory omitted them.
// A present zero is a real zero, not "unknown". Policy is the directory's
// policy text, not a verdict.
type LookupNetwork struct {
	ASN           uint32 `json:"asn"`
	Name          string `json:"name,omitempty"`
	Org           string `json:"org,omitempty"`
	Policy        string `json:"policy,omitempty"`
	PolicyURL     string `json:"policy_url,omitempty"`
	InfoPrefixes4 *int   `json:"info_prefixes4,omitempty"`
	InfoPrefixes6 *int   `json:"info_prefixes6,omitempty"`
}

// LookupMembership is one LAN attachment at a configured exchange.
// RouteServer is true when any merged source said the attachment peers
// with a route server.
type LookupMembership struct {
	Exchange    string `json:"exchange"`
	IXID        int    `json:"ix_id"`
	IXName      string `json:"ix_name,omitempty"`
	ASN         uint32 `json:"asn"`
	Name        string `json:"name,omitempty"`
	IPv4        string `json:"ipv4,omitempty"`
	IPv6        string `json:"ipv6,omitempty"`
	RouteServer bool   `json:"route_server"`
}
