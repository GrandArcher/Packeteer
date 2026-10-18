package plugin

import (
	"net/netip"
	"time"
)

// KindMemberSource is the read-only IX-F member import (#161).
// It is not a RIB source and it never announces.
const KindMemberSource Kind = "ixp_member"

// KindFabric is the IX fabric prober (#162). It measures member LAN
// addresses from configured vantages. It is not a provider, it is not an
// input to Decide, and it never announces.
const KindFabric Kind = "ixp_fabric"

// MemberSources is the registry for ixp.members.
var MemberSources = NewRegistry[MemberSource](KindMemberSource)

// FabricProbes is the registry for ixp.fabric.
var FabricProbes = NewRegistry[FabricProbe](KindFabric)

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
// the switch list of this connection's IXP when switch_id matches. A
// missing switch, or the same id on another IXP, leaves them empty.
// PhysSpeedMbps is set only when the export included if_phys_speed.
type IXPInterface struct {
	SwitchID      int    `json:"switch_id"`
	Switch        string `json:"switch,omitempty"`
	Colo          string `json:"colo,omitempty"`
	SpeedMbps     int    `json:"speed_mbps"`
	PhysSpeedMbps *int   `json:"if_phys_speed,omitempty"`
}

// IXPAddress is one LAN address on a connection.
// CanPing is IXP Manager's per-protocol opt-out when the export carries
// it. Nil means the document did not say. False means do not probe.
// BusyHost selects the looser ping tolerance (a slow control plane).
// Stock IX-F omits both; the fabric prober also reads them from IXP
// Manager's Nagios customer list when the import is the manager export.
type IXPAddress struct {
	Family      string `json:"family"`
	Address     string `json:"address"`
	VLANID      int    `json:"vlan_id,omitempty"`
	RouteServer bool   `json:"route_server"`
	MaxPrefix   int    `json:"max_prefix,omitempty"`
	ASMacro     string `json:"as_macro,omitempty"`
	CanPing     *bool  `json:"can_ping,omitempty"`
	BusyHost    bool   `json:"busy_host,omitempty"`
}

// FabricProbe measures member LAN addresses from IX vantages (#162).
// View never blocks and never fetches. SetMembers and SetVantages are
// called before Start. An implementation must not announce and must not
// write the RIB or call Decide.
type FabricProbe interface {
	Lifecycle
	View() FabricView
	SetMembers(fn func() MemberView)
	SetVantages(v []FabricVantage)
}

// FabricVantage is one IX-owned monitoring address on a peering LAN.
// IXPID 0 means the vlan id is unique in the member list.
type FabricVantage struct {
	Name    string
	IXPID   int
	VLANID  int
	Address netip.Addr
}

// FabricView is the latest fabric round. Samples is empty when probing
// is off, the member list is stale, or a vantage source cannot be used.
// The API key is never included.
type FabricView struct {
	Configured bool                  `json:"configured"`
	Stale      bool                  `json:"stale"`
	Error      string                `json:"error,omitempty"`
	Round      time.Time             `json:"round,omitempty"`
	Targets    int                   `json:"targets"`
	OptOut     int                   `json:"opt_out"`
	Vantages   []FabricVantageStatus `json:"vantages"`
	Samples    []FabricSample        `json:"samples"`
}

// FabricVantageStatus is one vantage after a round. Up is false when its
// address is not on the peering LAN or every probe from it failed.
type FabricVantageStatus struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	VLANID  int    `json:"vlan_id"`
	IXPID   int    `json:"ixp_id,omitempty"`
	Up      bool   `json:"up"`
	Targets int    `json:"targets"`
	Error   string `json:"error,omitempty"`
}

// FabricSwitch is one switch behind a member connection.
type FabricSwitch struct {
	ID   int    `json:"id"`
	Name string `json:"name,omitempty"`
	Colo string `json:"colo,omitempty"`
}

// FabricSample is one member address measured from one vantage.
// PastTolerance uses IXP Manager's ping warning (busy-host when set).
// An Error means the probe did not produce a measurement.
type FabricSample struct {
	Vantage       string         `json:"vantage"`
	ASN           uint32         `json:"asn"`
	Name          string         `json:"name,omitempty"`
	Address       string         `json:"address"`
	Family        string         `json:"family"`
	VLANID        int            `json:"vlan_id"`
	IXPID         int            `json:"ixp_id"`
	Switches      []FabricSwitch `json:"switches,omitempty"`
	BusyHost      bool           `json:"busy_host"`
	Sent          int            `json:"sent"`
	Received      int            `json:"received"`
	LossPct       float64        `json:"loss_pct"`
	RTTMs         float64        `json:"rtt_ms"`
	JitterMs      float64        `json:"jitter_ms"`
	PastTolerance bool           `json:"past_tolerance"`
	Error         string         `json:"error,omitempty"`
	At            time.Time      `json:"at"`
}
