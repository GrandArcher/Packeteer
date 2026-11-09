package federation

import "github.com/GrandArcher/Packeteer/pkg/plugin"

// PushableSections are the config sections one instance may push to its
// peers (#137). Everything that decides whether or what an instance
// announces stays out: mode, allowlist, announcer, bgp, inbound, and
// mitigation are never pushed, and a peer refuses them.
var PushableSections = []string{"thresholds", "policies"}

// PeerPush is one peer's answer to a push, or why none arrived.
type PeerPush struct {
	Peer    string   `json:"peer"`
	Status  string   `json:"status"`
	Applied []string `json:"applied,omitempty"`
	Errors  []string `json:"errors,omitempty"`
}

// PushReport is the per-peer outcome of one push. OK is true when every
// peer applied the sections or already had them.
type PushReport struct {
	Sections []string   `json:"sections"`
	OK       bool       `json:"ok"`
	Peers    []PeerPush `json:"peers"`
}

// Unreachable is the status of a peer that gave no answer.
const Unreachable = "unreachable"

// NewPushReport sets OK from the peers.
func NewPushReport(sections []string, peers []PeerPush) PushReport {
	r := PushReport{Sections: sections, Peers: peers, OK: len(peers) > 0}
	for _, p := range peers {
		if p.Status != plugin.SettingsApplied && p.Status != plugin.SettingsUnchanged {
			r.OK = false
		}
	}
	return r
}
