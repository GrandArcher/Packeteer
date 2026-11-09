package configedit

import (
	"strconv"

	"gopkg.in/yaml.v3"
)

// WizardPrefill is what the setup wizard shows in its fields when the file
// already has a setup, so the fields hold real values and never an example
// (#350). Providers is the file's list as written: an IPv6 twin appears as
// its own row.
type WizardPrefill struct {
	ASN       uint32           `json:"asn,omitempty"`
	RouterID  string           `json:"router_id,omitempty"`
	Edge      string           `json:"edge,omitempty"`
	Providers []WizardProvider `json:"providers,omitempty"`
}

// PrefillWizard reads the wizard fields out of data. It returns nil when
// data is not a mapping or has nothing to show.
func PrefillWizard(data []byte) *WizardPrefill {
	root, err := mappingRoot(data)
	if err != nil {
		return nil
	}
	out := WizardPrefill{RouterID: scalar(root, "router_id")}
	if n, err := strconv.ParseUint(scalar(root, "asn"), 10, 32); err == nil {
		out.ASN = uint32(n)
	}
	if addrs := neighborAddrs(root); len(addrs) > 0 {
		out.Edge = addrs[0]
	}
	if seq, ok := sequenceChild(root, "providers"); ok {
		for _, item := range seq.Content {
			if item.Kind != yaml.MappingNode {
				continue
			}
			p := WizardProvider{Name: scalar(item, "name"), SourceIP: scalar(item, "source_ip"), NextHop: scalar(item, "next_hop"), Type: scalar(item, "type")}
			if n, err := strconv.ParseUint(scalar(item, "asn"), 10, 32); err == nil {
				p.ASN = uint32(n)
			}
			out.Providers = append(out.Providers, p)
		}
	}
	if out.ASN == 0 && out.RouterID == "" && out.Edge == "" && len(out.Providers) == 0 {
		return nil
	}
	return &out
}
