package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// fakeIdP is an in-process OpenID provider: discovery, JWKS, and a token
// endpoint that checks the code and the PKCE verifier. No real network.
type fakeIdP struct {
	srv      *httptest.Server
	key      *rsa.PrivateKey
	signKey  *rsa.PrivateKey // normally key; another key forges a token
	code     string
	claims   map[string]any
	lastBody url.Values
}

func newIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: key, signKey: key, code: "good-code"}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize", "token_endpoint": f.srv.URL + "/token",
			"jwks_uri": f.srv.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.lastBody = r.PostForm
		if r.PostForm.Get("code") != f.code {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.signKey}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
		if err != nil {
			t.Error(err)
			return
		}
		raw, err := jwt.Signed(sig).Claims(f.claims).Serialize()
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 60, "id_token": raw})
	})
	return f
}

func (f *fakeIdP) baseClaims(nonce string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": f.srv.URL, "aud": "packeteer", "sub": "u-1", "exp": now.Add(time.Minute).Unix(), "iat": now.Unix(),
		"nonce": nonce, "email": "noc@example.net", "email_verified": true, "groups": []string{"staff", "noc-ops"},
	}
}

func newPlugin(t *testing.T, issuer, extra string) *Plugin {
	t.Helper()
	c, err := plugin.ConfigFromYAML("issuer: " + issuer + "\nclient_id: packeteer\nclient_secret_env: OIDC_SECRET\nredirect_url: https://packeteer.example.net/auth/callback\n" + extra)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(c, plugin.Env{Getenv: func(k string) string {
		if k == "OIDC_SECRET" {
			return "test-secret"
		}
		return ""
	}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestRegistered(t *testing.T) {
	if !plugin.SSOs.Has(TypeName) {
		t.Fatal("oidc not registered")
	}
}

func TestConfigValidation(t *testing.T) {
	env := plugin.Env{Getenv: func(k string) string {
		if k == "S" {
			return "x"
		}
		return ""
	}}
	base := "client_id: c\nclient_secret_env: S\nredirect_url: https://p.example.net/auth/callback\nrole_map: {g: admin}\n"
	good := []string{
		"issuer: https://idp.example.net\n" + base,
		"issuer: http://127.0.0.1:5556\n" + base,
		"issuer: https://idp.example.net\nclient_id: c\nclient_secret_env: S\nredirect_url: http://localhost:8080/auth/callback\ndefault_role: viewer\n",
	}
	for _, g := range good {
		c, _ := plugin.ConfigFromYAML(g)
		if _, err := New(c, env); err != nil {
			t.Errorf("%q: %v", g, err)
		}
	}
	bad := map[string]string{
		"http issuer":      "issuer: http://idp.example.net\n" + base,
		"no issuer":        base,
		"secret in file":   "issuer: https://idp.example.net\nclient_id: c\nclient_secret: x\nredirect_url: https://p.example.net/auth/callback\nrole_map: {g: admin}\n",
		"empty secret env": "issuer: https://idp.example.net\nclient_id: c\nclient_secret_env: NOPE\nredirect_url: https://p.example.net/auth/callback\nrole_map: {g: admin}\n",
		"no client id":     "issuer: https://idp.example.net\nclient_secret_env: S\nredirect_url: https://p.example.net/auth/callback\nrole_map: {g: admin}\n",
		"wrong path":       "issuer: https://idp.example.net\nclient_id: c\nclient_secret_env: S\nredirect_url: https://p.example.net/cb\nrole_map: {g: admin}\n",
		"bad role":         "issuer: https://idp.example.net\nclient_id: c\nclient_secret_env: S\nredirect_url: https://p.example.net/auth/callback\nrole_map: {g: root}\n",
		"no roles":         "issuer: https://idp.example.net\nclient_id: c\nclient_secret_env: S\nredirect_url: https://p.example.net/auth/callback\n",
		"bad default":      "issuer: https://idp.example.net\nclient_id: c\nclient_secret_env: S\nredirect_url: https://p.example.net/auth/callback\ndefault_role: god\n",
		"unknown key":      "issuer: https://idp.example.net\n" + base + "nope: 1\n",
	}
	for name, b := range bad {
		c, _ := plugin.ConfigFromYAML(b)
		if _, err := New(c, env); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestCodeFlow(t *testing.T) {
	idp := newIdP(t)
	p := newPlugin(t, idp.srv.URL, "role_map: {staff: viewer, noc-ops: operator, noc-admins: admin}\n")
	ctx := context.Background()
	if err := p.Start(ctx); err != nil {
		t.Fatal(err)
	}
	verifier := strings.Repeat("v", 64)
	u, err := p.AuthURL(ctx, "st", "nonce-1", verifier)
	if err != nil {
		t.Fatal(err)
	}
	q, _ := url.Parse(u)
	sum := sha256.Sum256([]byte(verifier))
	if !strings.HasPrefix(u, idp.srv.URL+"/authorize?") || q.Query().Get("state") != "st" || q.Query().Get("nonce") != "nonce-1" ||
		q.Query().Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) || q.Query().Get("code_challenge_method") != "S256" ||
		!strings.Contains(q.Query().Get("scope"), "openid") {
		t.Fatalf("auth url: %s", u)
	}

	// The highest mapped group wins.
	idp.claims = idp.baseClaims("nonce-1")
	id, err := p.Exchange(ctx, "good-code", "nonce-1", verifier)
	if err != nil {
		t.Fatal(err)
	}
	if id.User != "noc@example.net" || id.Role != plugin.RoleOperator || id.Subject != "u-1" {
		t.Fatalf("identity: %+v", id)
	}
	if idp.lastBody.Get("code_verifier") != verifier {
		t.Fatalf("PKCE verifier not sent: %v", idp.lastBody)
	}

	cases := map[string]func(){
		"wrong nonce":    func() { idp.claims = idp.baseClaims("other") },
		"wrong audience": func() { idp.claims = idp.baseClaims("nonce-1"); idp.claims["aud"] = "someone-else" },
		"expired":        func() { idp.claims = idp.baseClaims("nonce-1"); idp.claims["exp"] = time.Now().Add(-time.Hour).Unix() },
		"unverified":     func() { idp.claims = idp.baseClaims("nonce-1"); idp.claims["email_verified"] = false },
		"no group":       func() { idp.claims = idp.baseClaims("nonce-1"); idp.claims["groups"] = []string{"visitors"} },
		"no email":       func() { idp.claims = idp.baseClaims("nonce-1"); delete(idp.claims, "email") },
		"forged": func() {
			idp.claims = idp.baseClaims("nonce-1")
			other, _ := rsa.GenerateKey(rand.Reader, 2048)
			idp.signKey = other
		},
	}
	for name, setup := range cases {
		idp.signKey = idp.key
		setup()
		if id, err := p.Exchange(ctx, "good-code", "nonce-1", verifier); err == nil {
			t.Errorf("%s: accepted %+v", name, id)
		}
	}
	idp.signKey = idp.key
	idp.claims = idp.baseClaims("nonce-1")
	if _, err := p.Exchange(ctx, "bad-code", "nonce-1", verifier); err == nil {
		t.Error("bad code accepted")
	}
}

func TestDefaultRoleAndStringClaim(t *testing.T) {
	idp := newIdP(t)
	p := newPlugin(t, idp.srv.URL, "default_role: viewer\nrole_map: {ops: admin}\nroles_claim: team\nusername_claim: preferred_username\n")
	ctx := context.Background()
	idp.claims = idp.baseClaims("n")
	idp.claims["preferred_username"] = "alice"
	id, err := p.Exchange(ctx, "good-code", "n", strings.Repeat("v", 64))
	if err != nil || id.User != "alice" || id.Role != plugin.RoleViewer {
		t.Fatalf("default role: %+v %v", id, err)
	}
	idp.claims["team"] = "ops"
	id, err = p.Exchange(ctx, "good-code", "n", strings.Repeat("v", 64))
	if err != nil || id.Role != plugin.RoleAdmin {
		t.Fatalf("string claim: %+v %v", id, err)
	}
}

func TestProviderDownAtStart(t *testing.T) {
	p := newPlugin(t, "http://127.0.0.1:1", "default_role: viewer\n")
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("start must not fail when the provider is down: %v", err)
	}
	if _, err := p.AuthURL(context.Background(), "s", "n", "v"); err == nil {
		t.Fatal("auth url without discovery")
	}
}
