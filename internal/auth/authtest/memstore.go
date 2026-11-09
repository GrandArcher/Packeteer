// Package authtest is an in-memory user and audit store for tests.
package authtest

import (
	"context"
	"errors"
	"sort"
	"sync"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Store implements plugin.UserStore and plugin.AuditStore in memory.
// Set Fail to make every call return an error.
type Store struct {
	mu     sync.Mutex
	users  map[string]plugin.User
	tokens map[string]plugin.APIToken
	audit  []plugin.AuditRecord
	Fail   bool
}

// New returns an empty store.
func New() *Store {
	return &Store{users: map[string]plugin.User{}, tokens: map[string]plugin.APIToken{}}
}

var errFail = errors.New("store failure")

func (s *Store) Users(context.Context) ([]plugin.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Fail {
		return nil, errFail
	}
	out := make([]plugin.User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) User(_ context.Context, name string) (plugin.User, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Fail {
		return plugin.User{}, false, errFail
	}
	u, ok := s.users[name]
	return u, ok, nil
}

func (s *Store) PutUser(_ context.Context, u plugin.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Fail {
		return errFail
	}
	s.users[u.Name] = u
	return nil
}

func (s *Store) DeleteUser(_ context.Context, name string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Fail {
		return false, errFail
	}
	_, ok := s.users[name]
	delete(s.users, name)
	for id, t := range s.tokens {
		if t.User == name {
			delete(s.tokens, id)
		}
	}
	return ok, nil
}

func (s *Store) Tokens(context.Context) ([]plugin.APIToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Fail {
		return nil, errFail
	}
	out := make([]plugin.APIToken, 0, len(s.tokens))
	for _, t := range s.tokens {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Store) Token(_ context.Context, id string) (plugin.APIToken, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Fail {
		return plugin.APIToken{}, false, errFail
	}
	t, ok := s.tokens[id]
	return t, ok, nil
}

func (s *Store) PutToken(_ context.Context, t plugin.APIToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Fail {
		return errFail
	}
	s.tokens[t.ID] = t
	return nil
}

func (s *Store) DeleteToken(_ context.Context, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Fail {
		return false, errFail
	}
	_, ok := s.tokens[id]
	delete(s.tokens, id)
	return ok, nil
}

func (s *Store) AppendAudit(_ context.Context, r plugin.AuditRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Fail {
		return errFail
	}
	s.audit = append(s.audit, r)
	return nil
}

func (s *Store) Audit(_ context.Context, q plugin.AuditQuery) ([]plugin.AuditRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Fail {
		return nil, errFail
	}
	var out []plugin.AuditRecord
	for i := len(s.audit) - 1; i >= 0; i-- {
		r := s.audit[i]
		if (!q.From.IsZero() && r.Time.Before(q.From)) || (!q.To.IsZero() && !r.Time.Before(q.To)) {
			continue
		}
		out = append(out, r)
		if q.Limit > 0 && len(out) == q.Limit {
			break
		}
	}
	return out, nil
}

// Records returns every audit record, oldest first.
func (s *Store) Records() []plugin.AuditRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]plugin.AuditRecord(nil), s.audit...)
}
