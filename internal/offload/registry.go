package offload

import (
	"errors"
	"fmt"
	"sort"
)

// ErrUnknownProfile is returned for a profile ID that is not registered.
var ErrUnknownProfile = errors.New("offload: unknown profile")

// IDs of the two built-in profiles.
const (
	NoneID   = "none"
	RefuseID = "refuse"
)

// NoneProfile is for platforms with no hardware forwarding table to offload to:
// software routers, CPU-only MikroTik, and CHR.
func NoneProfile() Profile {
	return Profile{
		ID:     NoneID,
		Status: Verified,
		MaxRun: Report,
		DefaultPolicy: DefaultPolicy{
			Kind:   NotApplicable,
			Reason: "not applicable: the platform forwards in software",
		},
		Miss:      Unknown,
		Selection: ObserveFlags,
	}
}

// RefuseProfile is for platforms no one has verified: Nokia 7250 and 7750, Cisco
// Nexus 3k and 9k, Juniper ACX and non-4600 EX, Extreme, and UniFi.
func RefuseProfile() Profile {
	return Profile{
		ID:     RefuseID,
		Status: Unverified,
		MaxRun: Refuse,
		DefaultPolicy: DefaultPolicy{
			Kind:   NotApplicable,
			Reason: "platform not supported, nothing evaluated",
		},
		Miss:      Unknown,
		Selection: ObserveFlags,
	}
}

// Registry holds profiles by ID.
type Registry struct {
	profiles map[string]Profile
}

// NewRegistry returns a registry with the none and refuse profiles.
func NewRegistry() *Registry {
	r := &Registry{profiles: map[string]Profile{}}
	for _, p := range []Profile{NoneProfile(), RefuseProfile()} {
		if err := r.Register(p); err != nil {
			panic(err)
		}
	}
	return r
}

// Register adds a valid profile. A duplicate ID is an error.
func (r *Registry) Register(p Profile) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if _, dup := r.profiles[p.ID]; dup {
		return fmt.Errorf("offload: profile %q already registered", p.ID)
	}
	r.profiles[p.ID] = p
	return nil
}

// Get returns the profile for id, or ErrUnknownProfile.
func (r *Registry) Get(id string) (Profile, error) {
	p, ok := r.profiles[id]
	if !ok {
		return Profile{}, fmt.Errorf("%w: %q", ErrUnknownProfile, id)
	}
	return p, nil
}

// IDs returns the registered IDs, sorted.
func (r *Registry) IDs() []string {
	ids := make([]string, 0, len(r.profiles))
	for id := range r.profiles {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
