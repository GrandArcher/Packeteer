package plugin

import "time"

// KindMemberSource is the read-only IX-F member import (#161).
// It is not a RIB source and it never announces.
const KindMemberSource Kind = "ixp_member"

// MemberSources is the registry for ixp.members.
var MemberSources = NewRegistry[MemberSource](KindMemberSource)

// MemberSource imports an IX-F member list. View never blocks and never
// fetches. The slices it returns must not be modified. SetEventSink is
// called before Start; the sink is how a key-expiry warning is delivered.
// An implementation must not announce and must not write the RIB.
type MemberSource interface {
	Lifecycle
	View() MemberView
	SetEventSink(fn func(Event))
}

// MemberView is one imported member list. Counts are zero and the lists
// are empty when the import is not configured, has not succeeded, or has
// gone stale. KeyID is the key's identifier, never the secret.
type MemberView struct {
	Configured   bool        `json:"configured"`
	URL          string      `json:"url,omitempty"`
	Manager      bool        `json:"manager"`
	KeyID        string      `json:"key_id,omitempty"`
	KeyExpires   time.Time   `json:"key_expires,omitempty"`
	Fetched      time.Time   `json:"fetched,omitempty"`
	Stale        bool        `json:"stale"`
	Error        string      `json:"error,omitempty"`
	MemberCount  int         `json:"member_count"`
	AddressCount int         `json:"address_count"`
	IXPs         []IXPSite   `json:"ixps"`
	Members      []IXPMember `json:"members"`
}

// IXPSite is one exchange in the IX-F ixp_list.
type IXPSite struct {
	ID        int         `json:"ixp_id"`
	Shortname string      `json:"shortname,omitempty"`
	Name      string      `json:"name,omitempty"`
	VLANs     []IXPVLAN   `json:"vlans"`
	Switches  []IXPSwitch `json:"switches"`
}

// IXPVLAN is one peering LAN. IPv4 and IPv6 are CIDR prefixes.
type IXPVLAN struct {
	ID   int    `json:"id"`
	Name string `json:"name,omitempty"`
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
}

// IXPSwitch is one switch in the export. Colo is the cabinet name.
type IXPSwitch struct {
	ID           int    `json:"id"`
	Name         string `json:"name,omitempty"`
	Colo         string `json:"colo,omitempty"`
	City         string `json:"city,omitempty"`
	Country      string `json:"country,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Model        string `json:"model,omitempty"`
	Software     string `json:"software,omitempty"`
}

// IXPMember is one member ASN and its connections at the exchange.
type IXPMember struct {
	ASN         uint32          `json:"asn"`
	Name        string          `json:"name,omitempty"`
	Connections []IXPConnection `json:"connections"`
}

// IXPConnection is one member connection. State is the IX-F state string.
type IXPConnection struct {
	IXPID      int            `json:"ixp_id"`
	State      string         `json:"state,omitempty"`
	Interfaces []IXPInterface `json:"interfaces"`
	Addresses  []IXPAddress   `json:"addresses"`
}

// IXPInterface is one physical interface. Switch and Colo are copied from
// the switch list when switch_id matches; a missing switch leaves them
// empty. PhysSpeedMbps is set only when the export included if_phys_speed.
type IXPInterface struct {
	SwitchID      int    `json:"switch_id"`
	Switch        string `json:"switch,omitempty"`
	Colo          string `json:"colo,omitempty"`
	SpeedMbps     int    `json:"speed_mbps"`
	PhysSpeedMbps *int   `json:"if_phys_speed,omitempty"`
}

// IXPAddress is one LAN address on a connection.
type IXPAddress struct {
	Family      string `json:"family"`
	Address     string `json:"address"`
	VLANID      int    `json:"vlan_id,omitempty"`
	RouteServer bool   `json:"route_server"`
	MaxPrefix   int    `json:"max_prefix,omitempty"`
	ASMacro     string `json:"as_macro,omitempty"`
}
