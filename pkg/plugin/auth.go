package plugin

import (
	"context"
	"time"
)

// ---- Users, roles, audit, and single sign-on (#32) ----

// KindSSO is the single sign-on extension point.
const KindSSO Kind = "sso"

// Role is what an HTTP user may do. Each role includes the ones below it.
type Role string

// Roles, lowest first.
const (
	// RoleViewer reads the dashboard, the API, metrics, and reports, and
	// manages its own API tokens.
	RoleViewer Role = "viewer"
	// RoleOperator also opens and closes maintenance windows, adds and
	// removes mitigation rules, and runs the troubleshooting tools.
	RoleOperator Role = "operator"
	// RoleAdmin also manages users and reads the audit log.
	RoleAdmin Role = "admin"
)

var roleRank = map[Role]int{RoleViewer: 1, RoleOperator: 2, RoleAdmin: 3}

// Valid reports whether r is one of the three roles.
func (r Role) Valid() bool { return roleRank[r] > 0 }

// Allows reports whether r may do what need may do. An unknown role allows
// nothing.
func (r Role) Allows(need Role) bool {
	have, ok := roleRank[r]
	return ok && have >= roleRank[need] && roleRank[need] > 0
}

// MinRole returns the lower of two roles. An unknown role is lowest.
func MinRole(a, b Role) Role {
	if roleRank[a] <= roleRank[b] {
		return a
	}
	return b
}

// User sources.
const (
	UserLocal = "local"
	UserSSO   = "sso"
)

// User is an HTTP account. PasswordHash is set for local users only; an
// SSO user signs in through the identity provider.
type User struct {
	Name         string
	Role         Role
	Source       string
	PasswordHash string
	Disabled     bool
	Created      time.Time
	Updated      time.Time
}

// APIToken is a bearer token for scripts. Hash is the hex SHA-256 of the
// secret; the secret itself is shown once and never stored. A token's
// effective role is the lower of Role and its user's current role.
type APIToken struct {
	ID      string
	User    string
	Name    string
	Role    Role
	Hash    string
	Created time.Time
	Expires time.Time
}

// AuditRecord is one change or sign-in on the ops API, or a controller
// action taken by an operator (a config reload).
type AuditRecord struct {
	ID     string    `json:"id"`
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`
	Role   Role      `json:"role,omitempty"`
	Method string    `json:"method"` // password, token, sso, basic, system
	Remote string    `json:"remote,omitempty"`
	Action string    `json:"action"` // e.g. "POST /api/mitigations"
	Target string    `json:"target,omitempty"`
	Result string    `json:"result"` // ok, denied, failed
	Status int       `json:"status,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

// AuditQuery selects audit records whose Time is in [From, To). A zero
// bound is open. Limit caps the rows (newest first).
type AuditQuery struct {
	From  time.Time
	To    time.Time
	Limit int
}

// UserStore is optional on a storage plugin: HTTP users and API tokens
// (#32). The controller refuses to start with `auth` configured when the
// storage plugin does not implement it.
type UserStore interface {
	Users(ctx context.Context) ([]User, error)
	User(ctx context.Context, name string) (User, bool, error)
	// PutUser creates or replaces the user with that name.
	PutUser(ctx context.Context, u User) error
	// DeleteUser removes the user and every token of the user.
	DeleteUser(ctx context.Context, name string) (bool, error)
	Tokens(ctx context.Context) ([]APIToken, error)
	Token(ctx context.Context, id string) (APIToken, bool, error)
	PutToken(ctx context.Context, t APIToken) error
	DeleteToken(ctx context.Context, id string) (bool, error)
}

// AuditStore is optional on a storage plugin: the audit log (#32).
type AuditStore interface {
	AppendAudit(ctx context.Context, r AuditRecord) error
	// Audit returns matching records, newest first.
	Audit(ctx context.Context, q AuditQuery) ([]AuditRecord, error)
}

// SSOIdentity is a verified sign-in from an identity provider.
type SSOIdentity struct {
	// User is the account name (from the configured claim).
	User string
	// Subject is the provider's stable subject identifier.
	Subject string
	// Role is mapped from the provider's claims. It is always valid; a
	// sign-in with no mapped role is an error from Exchange.
	Role Role
}

// SSO is a single sign-on plugin (OIDC). It runs in-process and only
// establishes who a user is and which role the provider grants; it never
// announces routes or changes decisions.
type SSO interface {
	Lifecycle
	// AuthURL is where the browser is sent to sign in. state, nonce, and
	// verifier (PKCE) are fresh random values the core keeps. It fails
	// when the provider's discovery document cannot be read.
	AuthURL(ctx context.Context, state, nonce, verifier string) (string, error)
	// Exchange trades the callback code for a verified identity. It
	// checks the ID token signature, issuer, audience, expiry, and nonce.
	Exchange(ctx context.Context, code, nonce, verifier string) (SSOIdentity, error)
}

// SSOs is the single sign-on registry.
var SSOs = NewRegistry[SSO](KindSSO)
