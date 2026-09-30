// Package auth is HTTP authentication and role-based access for the ops
// API (#32): local users with passwords, API tokens, optional single
// sign-on through an sso plugin, and the audit log. Users and tokens live
// in the storage plugin (plugin.UserStore). Nothing here announces routes
// or changes decisions; it only decides who may call the API.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Sign-in methods recorded on a Principal and in the audit log.
const (
	MethodPassword = "password"
	MethodToken    = "token"
	MethodSSO      = "sso"
	// MethodBasic is the single PACKETEER_HTTP_USER account used when auth
	// is not configured.
	MethodBasic  = "basic"
	MethodSystem = "system"
)

// Defaults and bounds.
const (
	DefaultSessionTTL = 12 * time.Hour
	MinSessionTTL     = 5 * time.Minute
	MaxSessionTTL     = 7 * 24 * time.Hour
	DefaultTokenTTL   = 90 * 24 * time.Hour
	MaxTokenTTL       = 365 * 24 * time.Hour
	// MaxTokensPerUser caps live tokens per user.
	MaxTokensPerUser = 20

	// SessionCookie holds an SSO session id.
	SessionCookie = "packeteer_session"
	// StateCookie ties an SSO callback to the browser that started it.
	StateCookie = "packeteer_sso"

	loginTTL       = 10 * time.Minute
	maxPending     = 1000
	maxSessions    = 10000
	cacheTTL       = 5 * time.Minute
	failWindow     = 5 * time.Minute
	failLimit      = 10
	maxThrottleIPs = 10000
	tokenPrefix    = "pkt_"
)

// Errors.
var (
	ErrNoCredentials  = errors.New("no credentials")
	ErrBadCredentials = errors.New("invalid credentials")
	ErrThrottled      = errors.New("too many failed sign-ins; try again later")
	ErrUnavailable    = errors.New("user store unavailable")
	ErrNotFound       = errors.New("not found")
	ErrExists         = errors.New("already exists")
	ErrForbidden      = errors.New("forbidden")
	ErrLastAdmin      = errors.New("refused: this would leave no enabled admin")
	ErrNoSSO          = errors.New("single sign-on is not configured")
	// ErrInvalid wraps request validation errors.
	ErrInvalid = errors.New("invalid")
)

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Principal is who made a request.
type Principal struct {
	User    string      `json:"user"`
	Role    plugin.Role `json:"role"`
	Method  string      `json:"method"`
	TokenID string      `json:"token_id,omitempty"`
}

// Options configure a Service.
type Options struct {
	Users plugin.UserStore
	// SSO is nil when single sign-on is off.
	SSO        plugin.SSO
	SessionTTL time.Duration
	TokenTTL   time.Duration
	Logger     *slog.Logger
	Now        func() time.Time
}

type session struct {
	user    string
	expires time.Time
}

type pendingLogin struct {
	nonce    string
	verifier string
	expires  time.Time
}

type cached struct {
	key     [32]byte
	expires time.Time
}

type failures struct {
	count int
	start time.Time
}

// Service authenticates requests and manages users and tokens.
type Service struct {
	users      plugin.UserStore
	sso        plugin.SSO
	sessionTTL time.Duration
	tokenTTL   time.Duration
	log        *slog.Logger
	now        func() time.Time
	pepper     []byte

	// mu serializes user and token changes (the last-admin check).
	mu sync.Mutex

	smu      sync.Mutex
	sessions map[string]session
	pending  map[string]pendingLogin
	pwCache  map[string]cached
	fails    map[netip.Addr]*failures

	dummyOnce sync.Once
	dummy     string
}

// New validates options. It does not touch the store.
func New(o Options) (*Service, error) {
	if o.Users == nil {
		return nil, errors.New("auth: a user store is required")
	}
	if o.SessionTTL == 0 {
		o.SessionTTL = DefaultSessionTTL
	}
	if o.TokenTTL == 0 {
		o.TokenTTL = DefaultTokenTTL
	}
	if o.SessionTTL < MinSessionTTL || o.SessionTTL > MaxSessionTTL {
		return nil, fmt.Errorf("auth: session_ttl %s must be between %s and %s", o.SessionTTL, MinSessionTTL, MaxSessionTTL)
	}
	if o.TokenTTL < time.Hour || o.TokenTTL > MaxTokenTTL {
		return nil, fmt.Errorf("auth: token_ttl %s must be between 1h and %s", o.TokenTTL, MaxTokenTTL)
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	pepper := make([]byte, 32)
	if _, err := rand.Read(pepper); err != nil {
		return nil, err
	}
	return &Service{
		users: o.Users, sso: o.SSO, sessionTTL: o.SessionTTL, tokenTTL: o.TokenTTL, log: o.Logger, now: o.Now, pepper: pepper,
		sessions: map[string]session{}, pending: map[string]pendingLogin{}, pwCache: map[string]cached{}, fails: map[netip.Addr]*failures{},
	}, nil
}

// SSOEnabled reports whether single sign-on is configured.
func (s *Service) SSOEnabled() bool { return s != nil && s.sso != nil }

// RemoteIP is the request's peer address. X-Forwarded-For is ignored:
// behind a reverse proxy the proxy's address is what is seen.
func RemoteIP(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap().WithZone("")
}

// Authenticate identifies the caller from an Authorization header (Bearer
// token or Basic password) or an SSO session cookie. Failed passwords and
// tokens are counted per client address; past the limit every attempt
// from it fails with ErrThrottled until the window ends.
func (s *Service) Authenticate(r *http.Request) (Principal, error) {
	ip := RemoteIP(r)
	now := s.now()
	if s.throttled(ip, now) {
		return Principal{}, ErrThrottled
	}
	ctx := r.Context()
	if h := r.Header.Get("Authorization"); h != "" {
		scheme, cred, _ := strings.Cut(h, " ")
		var p Principal
		var err error
		switch strings.ToLower(scheme) {
		case "bearer":
			p, err = s.token(ctx, strings.TrimSpace(cred), now)
		case "basic":
			user, pass, ok := r.BasicAuth()
			if !ok {
				err = ErrBadCredentials
				break
			}
			p, err = s.password(ctx, user, pass, now)
		default:
			err = ErrBadCredentials
		}
		if errors.Is(err, ErrBadCredentials) {
			s.fail(ip, now)
		}
		return p, err
	}
	if c, err := r.Cookie(SessionCookie); err == nil && c.Value != "" {
		p, err := s.session(ctx, c.Value, now)
		if errors.Is(err, ErrBadCredentials) {
			// An expired or unknown session is the same as none: the
			// browser is sent to sign in again.
			return Principal{}, ErrNoCredentials
		}
		return p, err
	}
	return Principal{}, ErrNoCredentials
}

func (s *Service) throttled(ip netip.Addr, now time.Time) bool {
	s.smu.Lock()
	defer s.smu.Unlock()
	f := s.fails[ip]
	if f == nil {
		return false
	}
	if now.Sub(f.start) >= failWindow {
		delete(s.fails, ip)
		return false
	}
	return f.count >= failLimit
}

func (s *Service) fail(ip netip.Addr, now time.Time) {
	s.smu.Lock()
	defer s.smu.Unlock()
	if len(s.fails) >= maxThrottleIPs {
		for k, f := range s.fails {
			if now.Sub(f.start) >= failWindow {
				delete(s.fails, k)
			}
		}
	}
	f := s.fails[ip]
	if f == nil || now.Sub(f.start) >= failWindow {
		f = &failures{start: now}
		s.fails[ip] = f
	}
	f.count++
	if f.count == failLimit {
		s.log.Warn("http auth: too many failed sign-ins; throttling", "remote", ip.String(), "window", failWindow)
	}
}

func (s *Service) dummyHash() string {
	s.dummyOnce.Do(func() {
		s.dummy, _ = HashPassword(randomHex(16))
	})
	return s.dummy
}

func (s *Service) password(ctx context.Context, name, pw string, now time.Time) (Principal, error) {
	u, ok, err := s.users.User(ctx, name)
	if err != nil {
		return Principal{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if !ok || u.Source != plugin.UserLocal || u.PasswordHash == "" || u.Disabled || !u.Role.Valid() {
		// Same cost as a real check, so a missing user is not faster.
		VerifyPassword(s.dummyHash(), pw)
		return Principal{}, ErrBadCredentials
	}
	key := s.cacheKey(u.PasswordHash, pw)
	s.smu.Lock()
	c, hit := s.pwCache[name]
	s.smu.Unlock()
	if !hit || now.After(c.expires) || subtle.ConstantTimeCompare(c.key[:], key[:]) != 1 {
		if !VerifyPassword(u.PasswordHash, pw) {
			return Principal{}, ErrBadCredentials
		}
		s.smu.Lock()
		s.pwCache[name] = cached{key: key, expires: now.Add(cacheTTL)}
		s.smu.Unlock()
	}
	return Principal{User: u.Name, Role: u.Role, Method: MethodPassword}, nil
}

// cacheKey binds a verified password to the stored hash, so a password
// change invalidates the cache. The pepper is per process.
func (s *Service) cacheKey(hash, pw string) [32]byte {
	h := sha256.New()
	h.Write(s.pepper)
	h.Write([]byte(hash))
	h.Write([]byte{0})
	h.Write([]byte(pw))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func tokenHash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func parseToken(raw string) (id, secret string, ok bool) {
	rest, found := strings.CutPrefix(raw, tokenPrefix)
	if !found {
		return "", "", false
	}
	id, secret, found = strings.Cut(rest, "_")
	if !found || len(id) != 16 || len(secret) < 32 || len(secret) > 64 {
		return "", "", false
	}
	if _, err := hex.DecodeString(id); err != nil {
		return "", "", false
	}
	return id, secret, true
}

func (s *Service) token(ctx context.Context, raw string, now time.Time) (Principal, error) {
	id, secret, ok := parseToken(raw)
	if !ok {
		return Principal{}, ErrBadCredentials
	}
	t, found, err := s.users.Token(ctx, id)
	if err != nil {
		return Principal{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if !found || subtle.ConstantTimeCompare([]byte(tokenHash(secret)), []byte(t.Hash)) != 1 {
		return Principal{}, ErrBadCredentials
	}
	if !t.Expires.IsZero() && !now.Before(t.Expires) {
		return Principal{}, ErrBadCredentials
	}
	u, found, err := s.users.User(ctx, t.User)
	if err != nil {
		return Principal{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if !found || u.Disabled {
		return Principal{}, ErrBadCredentials
	}
	role := plugin.MinRole(t.Role, u.Role)
	if !role.Valid() {
		return Principal{}, ErrBadCredentials
	}
	return Principal{User: u.Name, Role: role, Method: MethodToken, TokenID: t.ID}, nil
}

func (s *Service) session(ctx context.Context, id string, now time.Time) (Principal, error) {
	s.smu.Lock()
	ss, ok := s.sessions[id]
	if ok && !now.Before(ss.expires) {
		delete(s.sessions, id)
		ok = false
	}
	s.smu.Unlock()
	if !ok {
		return Principal{}, ErrBadCredentials
	}
	u, found, err := s.users.User(ctx, ss.user)
	if err != nil {
		return Principal{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if !found || u.Disabled || !u.Role.Valid() {
		s.smu.Lock()
		delete(s.sessions, id)
		s.smu.Unlock()
		return Principal{}, ErrBadCredentials
	}
	return Principal{User: u.Name, Role: u.Role, Method: MethodSSO}, nil
}

// ---- Single sign-on ----

// BeginLogin redirects the browser to the identity provider.
func (s *Service) BeginLogin(w http.ResponseWriter, r *http.Request) error {
	if s.sso == nil {
		return ErrNoSSO
	}
	now := s.now()
	state, nonce, verifier := randomToken(), randomToken(), randomToken()+randomToken()
	s.smu.Lock()
	for k, p := range s.pending {
		if !now.Before(p.expires) {
			delete(s.pending, k)
		}
	}
	if len(s.pending) >= maxPending {
		s.smu.Unlock()
		return errors.New("too many sign-ins in progress; try again later")
	}
	s.pending[state] = pendingLogin{nonce: nonce, verifier: verifier, expires: now.Add(loginTTL)}
	s.smu.Unlock()
	u, err := s.sso.AuthURL(r.Context(), state, nonce, verifier)
	if err != nil {
		s.smu.Lock()
		delete(s.pending, state)
		s.smu.Unlock()
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: StateCookie, Value: state, Path: "/auth", MaxAge: int(loginTTL / time.Second),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, u, http.StatusFound)
	return nil
}

// FinishLogin completes the SSO callback, records the user in the store
// with the role the provider granted, and starts a session. A local user
// with the same name, or a disabled SSO user, is refused. The returned
// name is the user that tried to sign in, when known.
func (s *Service) FinishLogin(w http.ResponseWriter, r *http.Request) (Principal, string, error) {
	if s.sso == nil {
		return Principal{}, "", ErrNoSSO
	}
	// The state cookie is single use.
	http.SetCookie(w, &http.Cookie{Name: StateCookie, Value: "", Path: "/auth", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		return Principal{}, "", fmt.Errorf("identity provider: %.200s", e)
	}
	state, code := q.Get("state"), q.Get("code")
	c, err := r.Cookie(StateCookie)
	if err != nil || state == "" || code == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(state)) != 1 {
		return Principal{}, "", errors.New("sign-in state does not match; start again")
	}
	now := s.now()
	s.smu.Lock()
	p, ok := s.pending[state]
	delete(s.pending, state)
	s.smu.Unlock()
	if !ok || !now.Before(p.expires) {
		return Principal{}, "", errors.New("sign-in expired; start again")
	}
	id, err := s.sso.Exchange(r.Context(), code, p.nonce, p.verifier)
	if err != nil {
		return Principal{}, "", err
	}
	if !ValidUserName(id.User) {
		return Principal{}, "", fmt.Errorf("identity provider user %q is not a valid account name", id.User)
	}
	if !id.Role.Valid() {
		return Principal{}, id.User, errors.New("identity provider granted no role")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, found, err := s.users.User(r.Context(), id.User)
	if err != nil {
		return Principal{}, id.User, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	switch {
	case found && u.Source != plugin.UserSSO:
		return Principal{}, id.User, fmt.Errorf("a local user named %q exists; single sign-on cannot use it", id.User)
	case found && u.Disabled:
		return Principal{}, id.User, fmt.Errorf("user %q is disabled", id.User)
	}
	if !found {
		u = plugin.User{Name: id.User, Source: plugin.UserSSO, Created: now.UTC()}
	}
	u.Role, u.Updated = id.Role, now.UTC()
	if err := s.users.PutUser(r.Context(), u); err != nil {
		return Principal{}, id.User, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	sid := randomToken()
	s.smu.Lock()
	if len(s.sessions) >= maxSessions {
		for k, ss := range s.sessions {
			if !now.Before(ss.expires) {
				delete(s.sessions, k)
			}
		}
	}
	if len(s.sessions) >= maxSessions {
		s.smu.Unlock()
		return Principal{}, id.User, errors.New("too many sessions; try again later")
	}
	s.sessions[sid] = session{user: u.Name, expires: now.Add(s.sessionTTL)}
	s.smu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: sid, Path: "/", MaxAge: int(s.sessionTTL / time.Second),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	return Principal{User: u.Name, Role: u.Role, Method: MethodSSO}, u.Name, nil
}

// Logout ends the request's SSO session, if any, and clears the cookie.
func (s *Service) Logout(w http.ResponseWriter, r *http.Request) (string, bool) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	c, err := r.Cookie(SessionCookie)
	if err != nil || c.Value == "" {
		return "", false
	}
	s.smu.Lock()
	defer s.smu.Unlock()
	ss, ok := s.sessions[c.Value]
	delete(s.sessions, c.Value)
	return ss.user, ok
}

func (s *Service) dropSessions(user string) {
	s.smu.Lock()
	defer s.smu.Unlock()
	for k, ss := range s.sessions {
		if ss.user == user {
			delete(s.sessions, k)
		}
	}
	delete(s.pwCache, user)
}

// ---- Users ----

// UserView is a user without the password hash.
type UserView struct {
	Name     string      `json:"name"`
	Role     plugin.Role `json:"role"`
	Source   string      `json:"source"`
	Disabled bool        `json:"disabled"`
	Created  time.Time   `json:"created"`
	Updated  time.Time   `json:"updated"`
}

func view(u plugin.User) UserView {
	return UserView{Name: u.Name, Role: u.Role, Source: u.Source, Disabled: u.Disabled, Created: u.Created, Updated: u.Updated}
}

// ValidUserName is 1-64 characters of letters, digits, '.', '_', '-', '+',
// and '@', starting with a letter or digit.
func ValidUserName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i, c := range s {
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if i == 0 && !alnum {
			return false
		}
		if !alnum && c != '.' && c != '_' && c != '-' && c != '@' && c != '+' {
			return false
		}
	}
	return true
}

// Users lists every user, sorted by name.
func (s *Service) Users(ctx context.Context) ([]UserView, error) {
	us, err := s.users.Users(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	out := make([]UserView, 0, len(us))
	for _, u := range us {
		out = append(out, view(u))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// HasUsers reports whether any user exists.
func (s *Service) HasUsers(ctx context.Context) (bool, error) {
	us, err := s.users.Users(ctx)
	return len(us) > 0, err
}

// CreateUser adds a local user.
func (s *Service) CreateUser(ctx context.Context, name string, role plugin.Role, password string) (UserView, error) {
	if !ValidUserName(name) {
		return UserView{}, invalid("name must be 1-64 characters of letters, digits, '.', '_', '-', '+', '@', starting with a letter or digit")
	}
	if !role.Valid() {
		return UserView{}, invalid("role must be viewer, operator, or admin")
	}
	if err := CheckPassword(password); err != nil {
		return UserView{}, invalid("%v", err)
	}
	hash, err := HashPassword(password)
	if err != nil {
		return UserView{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, found, err := s.users.User(ctx, name)
	if err != nil {
		return UserView{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if found {
		return UserView{}, ErrExists
	}
	now := s.now().UTC()
	u := plugin.User{Name: name, Role: role, Source: plugin.UserLocal, PasswordHash: hash, Created: now, Updated: now}
	if err := s.users.PutUser(ctx, u); err != nil {
		return UserView{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return view(u), nil
}

// UserUpdate changes a user. Nil fields stay.
type UserUpdate struct {
	Role     *plugin.Role `json:"role"`
	Password *string      `json:"password"`
	Disabled *bool        `json:"disabled"`
}

// UpdateUser changes a user's role, password, or disabled flag. An SSO
// user's role and password come from the identity provider; only
// disabled may be set. A change that leaves no enabled admin is refused.
func (s *Service) UpdateUser(ctx context.Context, name string, up UserUpdate) (UserView, error) {
	if up.Role == nil && up.Password == nil && up.Disabled == nil {
		return UserView{}, invalid("nothing to change (role, password, disabled)")
	}
	if up.Role != nil && !up.Role.Valid() {
		return UserView{}, invalid("role must be viewer, operator, or admin")
	}
	var hash string
	if up.Password != nil {
		if err := CheckPassword(*up.Password); err != nil {
			return UserView{}, invalid("%v", err)
		}
		h, err := HashPassword(*up.Password)
		if err != nil {
			return UserView{}, err
		}
		hash = h
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, found, err := s.users.User(ctx, name)
	if err != nil {
		return UserView{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if !found {
		return UserView{}, ErrNotFound
	}
	if u.Source == plugin.UserSSO && (up.Role != nil || up.Password != nil) {
		return UserView{}, invalid("an sso user's role and password come from the identity provider; only disabled can be set")
	}
	next := u
	if up.Role != nil {
		next.Role = *up.Role
	}
	if up.Password != nil {
		next.PasswordHash = hash
	}
	if up.Disabled != nil {
		next.Disabled = *up.Disabled
	}
	if err := s.keepAdmin(ctx, u, &next); err != nil {
		return UserView{}, err
	}
	next.Updated = s.now().UTC()
	if err := s.users.PutUser(ctx, next); err != nil {
		return UserView{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if next.Disabled || up.Password != nil || next.Role != u.Role {
		s.dropSessions(name)
	}
	return view(next), nil
}

// DeleteUser removes a user and the user's tokens.
func (s *Service) DeleteUser(ctx context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, found, err := s.users.User(ctx, name)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if !found {
		return ErrNotFound
	}
	if err := s.keepAdmin(ctx, u, nil); err != nil {
		return err
	}
	if _, err := s.users.DeleteUser(ctx, name); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	s.dropSessions(name)
	return nil
}

// keepAdmin refuses a change to cur (next nil: delete) that leaves no
// enabled admin. Callers hold s.mu.
func (s *Service) keepAdmin(ctx context.Context, cur plugin.User, next *plugin.User) error {
	wasAdmin := cur.Role == plugin.RoleAdmin && !cur.Disabled
	stillAdmin := next != nil && next.Role == plugin.RoleAdmin && !next.Disabled
	if !wasAdmin || stillAdmin {
		return nil
	}
	us, err := s.users.Users(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	for _, u := range us {
		if u.Name != cur.Name && u.Role == plugin.RoleAdmin && !u.Disabled {
			return nil
		}
	}
	return ErrLastAdmin
}

// Bootstrap creates the first admin from the environment. It does
// nothing when a user with that name exists, so a password changed
// through the API is not reset on restart.
func (s *Service) Bootstrap(ctx context.Context, name, password string) (bool, error) {
	if name == "" {
		name = "admin"
	}
	_, err := s.CreateUser(ctx, name, plugin.RoleAdmin, password)
	switch {
	case errors.Is(err, ErrExists):
		return false, nil
	case err != nil:
		return false, err
	}
	return true, nil
}

// ---- API tokens ----

// TokenView is a token without its hash.
type TokenView struct {
	ID      string      `json:"id"`
	User    string      `json:"user"`
	Name    string      `json:"name"`
	Role    plugin.Role `json:"role"`
	Created time.Time   `json:"created"`
	Expires time.Time   `json:"expires"`
	Expired bool        `json:"expired,omitempty"`
}

func (s *Service) tokenView(t plugin.APIToken) TokenView {
	return TokenView{ID: t.ID, User: t.User, Name: t.Name, Role: t.Role, Created: t.Created, Expires: t.Expires, Expired: !s.now().Before(t.Expires)}
}

// CreateToken issues a token for p's own user. The role defaults to p's
// role and may not exceed it. A token cannot create tokens, so a leaked
// token cannot outlive its own expiry. The secret is returned once.
func (s *Service) CreateToken(ctx context.Context, p Principal, name string, role plugin.Role, ttl time.Duration) (TokenView, string, error) {
	if p.Method == MethodToken {
		return TokenView{}, "", fmt.Errorf("%w: an API token cannot create tokens; sign in with a password or SSO", ErrForbidden)
	}
	if p.Method != MethodPassword && p.Method != MethodSSO {
		return TokenView{}, "", fmt.Errorf("%w: tokens need a user account", ErrForbidden)
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 || strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return TokenView{}, "", invalid("name must be 1-64 printable characters")
	}
	if role == "" {
		role = p.Role
	}
	if !role.Valid() {
		return TokenView{}, "", invalid("role must be viewer, operator, or admin")
	}
	if !p.Role.Allows(role) {
		return TokenView{}, "", fmt.Errorf("%w: a token cannot have a higher role than its user (%s)", ErrForbidden, p.Role)
	}
	if ttl == 0 {
		ttl = s.tokenTTL
	}
	if ttl < time.Minute || ttl > MaxTokenTTL {
		return TokenView{}, "", invalid("ttl must be between 1m and %s", MaxTokenTTL)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	all, err := s.users.Tokens(ctx)
	if err != nil {
		return TokenView{}, "", fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	live := 0
	for _, t := range all {
		if !now.Before(t.Expires) {
			_, _ = s.users.DeleteToken(ctx, t.ID)
			continue
		}
		if t.User == p.User {
			live++
		}
	}
	if live >= MaxTokensPerUser {
		return TokenView{}, "", invalid("user %s already has %d tokens; revoke one first", p.User, MaxTokensPerUser)
	}
	secret := randomToken()
	t := plugin.APIToken{ID: randomHex(8), User: p.User, Name: name, Role: role, Hash: tokenHash(secret), Created: now.UTC(), Expires: now.Add(ttl).UTC()}
	if err := s.users.PutToken(ctx, t); err != nil {
		return TokenView{}, "", fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return s.tokenView(t), tokenPrefix + t.ID + "_" + secret, nil
}

// Tokens lists p's tokens; an admin sees every user's.
func (s *Service) Tokens(ctx context.Context, p Principal) ([]TokenView, error) {
	all, err := s.users.Tokens(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	out := []TokenView{}
	for _, t := range all {
		if t.User == p.User || p.Role == plugin.RoleAdmin {
			out = append(out, s.tokenView(t))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].User != out[j].User {
			return out[i].User < out[j].User
		}
		return out[i].Created.Before(out[j].Created)
	})
	return out, nil
}

// RevokeToken deletes one of p's tokens; an admin may revoke any.
func (s *Service) RevokeToken(ctx context.Context, p Principal, id string) (TokenView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, found, err := s.users.Token(ctx, id)
	if err != nil {
		return TokenView{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if !found {
		return TokenView{}, ErrNotFound
	}
	if t.User != p.User && p.Role != plugin.RoleAdmin {
		// Not found, so other users' token ids are not confirmed.
		return TokenView{}, ErrNotFound
	}
	if _, err := s.users.DeleteToken(ctx, id); err != nil {
		return TokenView{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return s.tokenView(t), nil
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
