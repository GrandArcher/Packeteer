// Package invcommon holds what the NetBox and Peering Manager inventory
// plugins share: the base config block, a read-only paginated REST client,
// and the parsing of the per-provider values the operator keeps there.
// Requests are GET only. Redirects are not followed, so the API token cannot
// be sent to another host.
package invcommon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Defaults and bounds.
const (
	DefaultTimeout = 30 * time.Second
	minTimeout     = time.Second
	maxTimeout     = 2 * time.Minute
	maxBody        = 8 << 20
	pageSize       = 200
	maxPages       = 100
	maxTokenLen    = 256
	maxURLLen      = 512
)

// Common is the config block both plugins decode. Tag is required so that
// the plugin never imports every record of a large system of record.
type Common struct {
	BaseURL string        `yaml:"base_url"`
	Tag     string        `yaml:"tag"`
	Timeout time.Duration `yaml:"timeout"`
}

// Settings is a validated Common.
type Settings struct {
	Base    *url.URL
	Tag     string
	Timeout time.Duration
}

// Validate checks the config shape. https is required unless the host is a
// loopback address, which is how a lab runs. The token is not read here:
// the running controller loads the config but never reads the inventory, so
// it need not hold the token. Token reads it for a fetch.
func Validate(c Common) (Settings, error) {
	raw := strings.TrimSpace(c.BaseURL)
	u, err := url.Parse(raw)
	if raw == "" || len(raw) > maxURLLen || err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return Settings{}, errors.New("base_url must be an http or https URL with a host and no userinfo, query, or fragment")
	}
	if u.Scheme != "https" && !loopback(u.Hostname()) {
		return Settings{}, errors.New("base_url must be https (http is accepted only for a loopback address)")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	if !plugin.ValidLabel(c.Tag) {
		return Settings{}, errors.New("tag is required: 1-64 characters of letters, digits, '.', '_' or '-'")
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if timeout < minTimeout || timeout > maxTimeout {
		return Settings{}, fmt.Errorf("timeout %s must be between %s and %s", timeout, minTimeout, maxTimeout)
	}
	return Settings{Base: u, Tag: c.Tag, Timeout: timeout}, nil
}

// Token reads the required API token from tokenEnv. A base URL that holds
// the token is refused.
func Token(s Settings, tokenEnv string, getenv func(string) string) (string, error) {
	token := strings.TrimSpace(getenv(tokenEnv))
	if token == "" {
		return "", fmt.Errorf("the API token is required: set %s", tokenEnv)
	}
	if len(token) > maxTokenLen {
		return "", errors.New("API token is too long")
	}
	for _, r := range token {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) || unicode.IsSpace(r) {
			return "", errors.New("API token has an invalid character")
		}
	}
	if strings.Contains(s.Base.String(), token) {
		return "", errors.New("base_url must not contain the API token")
	}
	return token, nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

// Client is a read-only REST client for one base URL.
type Client struct {
	base   *url.URL
	auth   string
	token  string
	client *http.Client
}

var errNoRedirect = errors.New("redirects are not followed")

// NewClient returns a client that sends the token on every request, as
// scheme followed by a space ("Token", "Bearer").
func NewClient(s Settings, scheme, token string) *Client {
	return &Client{
		base: s.Base, auth: scheme + " " + token, token: token,
		client: &http.Client{
			Timeout:       s.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return errNoRedirect },
		},
	}
}

// page is the list envelope both systems use.
type page struct {
	Next    *string           `json:"next"`
	Results []json.RawMessage `json:"results"`
}

// GetAll reads every page of the list at path and calls each with every
// result. Paging is by limit and offset computed here; the server's next
// URL is only checked for presence, so a proxy that rewrites it cannot send
// the token to another host.
func (c *Client) GetAll(ctx context.Context, path string, query url.Values, each func(json.RawMessage) error) error {
	offset := 0
	for n := 0; ; n++ {
		if n == maxPages {
			return fmt.Errorf("GET %s: more than %d pages", path, maxPages)
		}
		q := url.Values{}
		for k, v := range query {
			q[k] = slices.Clone(v)
		}
		q.Set("limit", strconv.Itoa(pageSize))
		q.Set("offset", strconv.Itoa(offset))
		var p page
		if err := c.get(ctx, path, q, &p); err != nil {
			return err
		}
		for _, raw := range p.Results {
			if err := each(raw); err != nil {
				return err
			}
		}
		offset += len(p.Results)
		if p.Next == nil || len(p.Results) == 0 {
			return nil
		}
	}
}

func (c *Client) get(ctx context.Context, path string, q url.Values, out any) error {
	u := *c.base
	u.Path += path
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.auth)
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %s", path, c.redact(err.Error()))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", path, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return fmt.Errorf("GET %s: %s", path, c.redact(err.Error()))
	}
	if len(body) > maxBody {
		return fmt.Errorf("GET %s: response over %d bytes", path, maxBody)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("GET %s: not a list response: %v", path, err)
	}
	return nil
}

func (c *Client) redact(s string) string { return strings.ReplaceAll(s, c.token, "redacted") }

// Slug turns a display name into a provider name: lowercase letters and
// digits, with every other run of characters becoming one '-'. It is empty
// when nothing is left.
func Slug(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = false
			b.WriteRune(r)
		default:
			dash = true
		}
	}
	if b.Len() > 64 {
		return strings.TrimRight(b.String()[:64], "-")
	}
	return b.String()
}

// Provider builds the managed part of a provider from the operator's values
// in bag (type, source_ip, next_hop, communities). A bad value is an error
// that names the key.
func Provider(name string, asn uint32, bag map[string]any) (plugin.InventoryProvider, error) {
	p := plugin.InventoryProvider{Name: name, ASN: asn}
	var err error
	if p.Type, err = scalar(bag, "type"); err != nil {
		return p, err
	}
	if p.Type != "" && !slices.Contains(config.ProviderTypes, p.Type) {
		return p, fmt.Errorf("type %q is invalid (want %s)", p.Type, strings.Join(config.ProviderTypes, ", "))
	}
	for _, f := range []struct {
		key string
		dst *string
	}{{"source_ip", &p.SourceIP}, {"next_hop", &p.NextHop}} {
		v, err := scalar(bag, f.key)
		if err != nil {
			return p, err
		}
		if v != "" {
			a, err := netip.ParseAddr(v)
			if err != nil {
				return p, fmt.Errorf("%s %q is not a valid IP address", f.key, v)
			}
			v = a.String()
		}
		*f.dst = v
	}
	p.Communities, err = communities(bag["communities"])
	return p, err
}

func scalar(bag map[string]any, key string) (string, error) {
	switch v := bag[key].(type) {
	case nil:
		return "", nil
	case string:
		return strings.TrimSpace(v), nil
	default:
		return "", fmt.Errorf("%s must be a string", key)
	}
}

// communities accepts a list of strings or one string separated by commas,
// semicolons, or spaces, and returns canonical text without duplicates.
func communities(v any) ([]string, error) {
	var items []string
	switch x := v.(type) {
	case nil:
		return nil, nil
	case string:
		items = strings.FieldsFunc(x, func(r rune) bool { return r == ',' || r == ';' || unicode.IsSpace(r) })
	case []any:
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return nil, errors.New("communities must be strings")
			}
			items = append(items, strings.TrimSpace(s))
		}
	default:
		return nil, errors.New("communities must be a list or a string")
	}
	var out []string
	for _, s := range items {
		text, err := config.CommunityText(s)
		if err != nil {
			return nil, fmt.Errorf("community %q: %v", s, err)
		}
		if !slices.Contains(out, text) {
			out = append(out, text)
		}
	}
	return out, nil
}

// Result sorts providers by name. A name that two records share is skipped
// whole: neither record is trusted to be the one the operator meant.
func Result(providers []plugin.InventoryProvider, skips []plugin.InventorySkip) plugin.InventoryResult {
	count := map[string]int{}
	for _, p := range providers {
		count[p.Name]++
	}
	out := plugin.InventoryResult{Skipped: skips}
	reported := map[string]bool{}
	for _, p := range providers {
		if count[p.Name] > 1 {
			if !reported[p.Name] {
				reported[p.Name] = true
				out.Skipped = append(out.Skipped, plugin.InventorySkip{Name: p.Name, Reason: "more than one record has this provider name"})
			}
			continue
		}
		out.Providers = append(out.Providers, p)
	}
	byName := func(a, b plugin.InventoryProvider) int { return strings.Compare(a.Name, b.Name) }
	slices.SortFunc(out.Providers, byName)
	slices.SortFunc(out.Skipped, func(a, b plugin.InventorySkip) int { return strings.Compare(a.Name, b.Name) })
	return out
}
