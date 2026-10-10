package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Release assets. A release carries one static binary per architecture
// and the signed checksum file.
const (
	SumsAsset = "SHA256SUMS"
	SigAsset  = "SHA256SUMS.sig"
)

// AssetName is the release asset for this platform's binary.
func AssetName(goarch string) string { return "packeteer-linux-" + goarch }

// Size limits for what is read from the network.
const (
	maxListBody   = 4 << 20
	maxSmallAsset = 1 << 20
	maxBinary     = 256 << 20
	maxNotes      = 16 << 10
	listCount     = 10
)

// Release is one GitHub release, trimmed to what the page shows.
type Release struct {
	Tag        string    `json:"tag"`
	Name       string    `json:"name,omitempty"`
	Notes      string    `json:"notes,omitempty"`
	URL        string    `json:"url,omitempty"`
	Prerelease bool      `json:"prerelease,omitempty"`
	Published  time.Time `json:"published,omitzero"`
	// assets maps asset name to download URL.
	assets map[string]string
}

// Installable reports whether the release carries the signed checksum
// file and a binary for goarch.
func (r Release) Installable(goarch string) bool {
	for _, n := range []string{SumsAsset, SigAsset, AssetName(goarch)} {
		if r.assets[n] == "" {
			return false
		}
	}
	return true
}

type ghRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	HTMLURL     string    `json:"html_url"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// client reads releases and assets over HTTP.
type client struct {
	api  string
	repo string
	http *http.Client
}

// allowedURL accepts https, or http to a loopback host (a local mirror,
// and the tests' fake server).
func allowedURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("bad URL %q", raw)
	}
	if u.Scheme == "https" || (u.Scheme == "http" && loopbackHost(u.Hostname())) {
		return u, nil
	}
	return nil, fmt.Errorf("refusing non-https URL %q", raw)
}

func (c *client) get(ctx context.Context, raw string, limit int64, accept string) ([]byte, error) {
	if _, err := allowedURL(raw); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "packeteer-upgrade")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", redact(raw), resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("GET %s: larger than %d bytes", redact(raw), limit)
	}
	return data, nil
}

// stream copies a download into w, bounded by limit.
func (c *client) stream(ctx context.Context, raw string, limit int64, w io.Writer) error {
	if _, err := allowedURL(raw); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "packeteer-upgrade")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", redact(raw), resp.Status)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if n > limit {
		return fmt.Errorf("GET %s: larger than %d bytes", redact(raw), limit)
	}
	return nil
}

// redact drops a query string, which a signed download URL can carry.
func redact(raw string) string {
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		return raw[:i]
	}
	return raw
}

// releases lists the newest published releases, newest first. A tag that
// is not a version, a draft, and (unless allowed) a pre-release are
// skipped.
func (c *client) releases(ctx context.Context, prerelease bool) ([]Release, error) {
	data, err := c.get(ctx, fmt.Sprintf("%s/repos/%s/releases?per_page=%d", c.api, c.repo, 30), maxListBody, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	var raw []ghRelease
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("releases: %w", err)
	}
	var out []Release
	for _, g := range raw {
		if g.Draft || !ValidTag(g.TagName) || (g.Prerelease && !prerelease) {
			continue
		}
		r := Release{Tag: g.TagName, Name: g.Name, Notes: g.Body, URL: g.HTMLURL, Prerelease: g.Prerelease,
			Published: g.PublishedAt.UTC(), assets: map[string]string{}}
		if len(r.Notes) > maxNotes {
			r.Notes = r.Notes[:maxNotes] + "\n…"
		}
		for _, a := range g.Assets {
			if _, err := allowedURL(a.URL); err == nil {
				r.assets[a.Name] = a.URL
			}
		}
		out = append(out, r)
		if len(out) == listCount {
			break
		}
	}
	return out, nil
}

var errNoRelease = errors.New("no such release")

func loopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(h)
	return err == nil && a.IsLoopback()
}
