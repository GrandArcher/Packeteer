// Package peeringdb is the PeeringDB registry-hygiene plugin (#289). Check
// reads the operator's network record, exchange connections, facilities,
// and contacts with GET and compares them with what the network does. Push
// updates one field of the network or an exchange connection with PUT, only
// after a person confirmed the diff and only with an API key. It never
// announces and never changes the learned RIB.
package peeringdb

import (
	"bytes"
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

	"golang.org/x/time/rate"

	lookup "github.com/GrandArcher/Packeteer/internal/plugins/lookup/peeringdb"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the config type.
const TypeName = "peeringdb"

// Defaults and bounds. The pace is PeeringDB's published minimum gap, wider
// without a key, as in the lookup plugin.
const (
	DefaultTimeout = 30 * time.Second
	minTimeout     = time.Second
	maxTimeout     = 2 * time.Minute
	maxBody        = 8 << 20
	anonymousGap   = 3 * time.Second
	keyedGap       = 2 * time.Second
	// contactAge is how old a contact record may get before it is flagged.
	contactAge = 2 * 365 * 24 * time.Hour
)

// pushable names the fields a push may change, by PeeringDB object.
var pushable = map[string][]string{
	"net":      {"info_prefixes4", "info_prefixes6"},
	"netixlan": {"speed"},
}

func init() { plugin.RegistryCheckers.Register(TypeName, New) }

// Config is the plugin's config block.
type Config struct {
	BaseURL string        `yaml:"base_url"`
	Timeout time.Duration `yaml:"timeout"`
}

// Checker reads and updates PeeringDB.
type Checker struct {
	plugin.Base
	base   *url.URL
	apiKey string
	http   *http.Client
	limit  *rate.Limiter
	now    func() time.Time
}

// New validates the config and the key. It does not dial.
func New(c plugin.Config, env plugin.Env) (plugin.RegistryChecker, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	getenv := env.Getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	key, err := lookup.ParseKey(getenv(lookup.APIKeyEnv))
	if err != nil {
		return nil, err
	}
	base, err := lookup.ParseBase(cfg.BaseURL, key)
	if err != nil {
		return nil, err
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Timeout < minTimeout || cfg.Timeout > maxTimeout {
		return nil, fmt.Errorf("timeout %s must be between %s and %s", cfg.Timeout, minTimeout, maxTimeout)
	}
	gap := anonymousGap
	if key != "" {
		gap = keyedGap
	}
	return &Checker{
		base: base, apiKey: key, now: time.Now,
		limit: rate.NewLimiter(rate.Every(gap), 1),
		http: &http.Client{
			Timeout: cfg.Timeout,
			// A redirect would carry the key to another host.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// object is one PeeringDB record.
type object map[string]json.RawMessage

func (o object) str(k string) string {
	var s string
	_ = json.Unmarshal(o[k], &s)
	return s
}

func (o object) num(k string) (int, bool) {
	var n int
	if err := json.Unmarshal(o[k], &n); err != nil {
		return 0, false
	}
	return n, true
}

// get returns the data array of a list or detail request.
func (c *Checker) get(ctx context.Context, path string, q url.Values) ([]object, error) {
	if err := c.limit.Wait(ctx); err != nil {
		return nil, err
	}
	u := *c.base
	u.Path += path
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.New("peeringdb: bad url")
	}
	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Data []object `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("peeringdb: %s: not a PeeringDB document", path)
	}
	return doc.Data, nil
}

func (c *Checker) do(req *http.Request) ([]byte, error) {
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "packeteer")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Api-Key "+c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, errors.New("peeringdb: " + lookup.Redact(err.Error(), c.apiKey))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		return nil, errors.New("peeringdb: response unreadable or too large")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peeringdb: %s %s: HTTP %d", req.Method, req.URL.Path, resp.StatusCode)
	}
	return body, nil
}

// Check compares each ASN's PeeringDB records with the facts.
func (c *Checker) Check(ctx context.Context, f plugin.RegistryFacts) ([]plugin.RegistryFinding, error) {
	var out []plugin.RegistryFinding
	for _, asn := range f.ASNs {
		fs, err := c.checkASN(ctx, asn, f)
		if err != nil {
			return nil, err
		}
		out = append(out, fs...)
	}
	return out, nil
}

func (c *Checker) checkASN(ctx context.Context, asn uint32, f plugin.RegistryFacts) ([]plugin.RegistryFinding, error) {
	as := strconv.FormatUint(uint64(asn), 10)
	nets, err := c.get(ctx, "/api/net", url.Values{"asn": {as}})
	if err != nil {
		return nil, err
	}
	if len(nets) == 0 {
		return []plugin.RegistryFinding{{
			Kind: "pdb_net_missing", Severity: plugin.RegistryWarning, Registry: "peeringdb",
			Subject: "AS" + as,
			Message: fmt.Sprintf("PeeringDB has no network record for AS%s; peers cannot look up its prefix counts or exchange connections", as),
		}}, nil
	}
	net := nets[0]
	id, _ := net.num("id")
	out := c.maxPrefix(net, id, asn, f)

	ixlans, err := c.get(ctx, "/api/netixlan", url.Values{"asn": {as}})
	if err != nil {
		return nil, err
	}
	out = append(out, ixFindings(ixlans, asn, f.Sessions)...)

	facs, err := c.get(ctx, "/api/netfac", url.Values{"local_asn": {as}})
	if err != nil {
		return nil, err
	}
	if len(facs) == 0 {
		out = append(out, plugin.RegistryFinding{
			Kind: "pdb_facility_missing", Severity: plugin.RegistryWarning, Registry: "peeringdb",
			Subject: "AS" + as + " facilities",
			Message: fmt.Sprintf("AS%s lists no facility in PeeringDB; add the facilities where it has a presence", as),
		})
	}

	pocs, err := c.get(ctx, "/api/poc", url.Values{"net_id": {strconv.Itoa(id)}})
	if err != nil {
		return nil, err
	}
	return append(out, c.contactFindings(pocs, as)...), nil
}

// maxPrefix flags info_prefixes below the announced count (peers size
// their max-prefix limit from it and would drop the session) and below the
// announced count plus the headroom.
func (c *Checker) maxPrefix(net object, id int, asn uint32, f plugin.RegistryFacts) []plugin.RegistryFinding {
	var out []plugin.RegistryFinding
	for _, v := range []struct {
		field string
		count int
	}{{"info_prefixes4", f.Announced4[asn]}, {"info_prefixes6", f.Announced6[asn]}} {
		have, ok := net.num(v.field)
		if v.count == 0 || !ok {
			continue
		}
		want := v.count + (v.count*f.Headroom+99)/100
		if have >= want {
			continue
		}
		sev, msg := plugin.RegistryWarning, fmt.Sprintf("PeeringDB %s is %d and %d prefixes are announced with origin AS%d; a peer that limits at the PeeringDB value drops the session", v.field, have, v.count, asn)
		if have >= v.count {
			sev, msg = plugin.RegistryInfo, fmt.Sprintf("PeeringDB %s is %d, %d prefixes are announced with origin AS%d, and %d%% headroom is %d", v.field, have, v.count, asn, f.Headroom, want)
		}
		out = append(out, plugin.RegistryFinding{
			Kind: "pdb_maxprefix", Severity: sev, Registry: "peeringdb",
			Subject: fmt.Sprintf("AS%d %s", asn, v.field),
			Message: msg,
			Diff:    fmt.Sprintf("net %d\n- %s: %d\n+ %s: %d", id, v.field, have, v.field, want),
			Change:  &plugin.RegistryChange{Registry: TypeName, Op: "update_field", Class: "net", Key: strconv.Itoa(id), Field: v.field, Old: strconv.Itoa(have), New: strconv.Itoa(want)},
		})
	}
	return out
}

// ixFindings compares netixlan records with the configured sessions of the
// exchanges whose ix id is known. Without the network's own LAN addresses
// a session is not compared, and the finding says so.
func ixFindings(ixlans []object, asn uint32, sessions []plugin.RegistrySession) []plugin.RegistryFinding {
	var out []plugin.RegistryFinding
	checked := map[int]bool{}
	for _, s := range sessions {
		if s.IXID == 0 {
			continue
		}
		if len(s.Addrs) == 0 {
			out = append(out, plugin.RegistryFinding{
				Kind: "pdb_ix_unchecked", Severity: plugin.RegistryInfo, Registry: "peeringdb",
				Subject: fmt.Sprintf("AS%d %s", asn, s.Exchange),
				Message: fmt.Sprintf("exchanges %s sets no local_lan_addrs, so the PeeringDB connection records at ix %d are not compared", s.Exchange, s.IXID),
			})
			continue
		}
		checked[s.IXID] = true
		for _, a := range s.Addrs {
			rec, found := findIX(ixlans, s.IXID, a)
			switch {
			case !found:
				diff := fmt.Sprintf("+ netixlan ix_id %d, asn %d, address %s", s.IXID, asn, a)
				if s.SpeedMbps > 0 {
					diff += fmt.Sprintf(", speed %d", s.SpeedMbps)
				}
				out = append(out, plugin.RegistryFinding{
					Kind: "pdb_ix_missing", Severity: plugin.RegistryWarning, Registry: "peeringdb",
					Subject: fmt.Sprintf("AS%d %s %s", asn, s.Exchange, a),
					Message: fmt.Sprintf("%s at %s has no PeeringDB connection record", a, s.Exchange),
					Diff:    diff,
				})
			case s.SpeedMbps > 0:
				if have, ok := rec.num("speed"); ok && have != s.SpeedMbps {
					id, _ := rec.num("id")
					out = append(out, plugin.RegistryFinding{
						Kind: "pdb_ix_speed", Severity: plugin.RegistryWarning, Registry: "peeringdb",
						Subject: fmt.Sprintf("AS%d %s %s speed", asn, s.Exchange, a),
						Message: fmt.Sprintf("PeeringDB lists %d Mbps for %s at %s and the config says %d", have, a, s.Exchange, s.SpeedMbps),
						Diff:    fmt.Sprintf("netixlan %d\n- speed: %d\n+ speed: %d", id, have, s.SpeedMbps),
						Change:  &plugin.RegistryChange{Registry: TypeName, Op: "update_field", Class: "netixlan", Key: strconv.Itoa(id), Field: "speed", Old: strconv.Itoa(have), New: strconv.Itoa(s.SpeedMbps)},
					})
				}
			}
		}
	}
	for _, rec := range ixlans {
		ix, _ := rec.num("ix_id")
		if !checked[ix] {
			continue
		}
		configured := false
		var listed []string
		for _, k := range []string{"ipaddr4", "ipaddr6"} {
			if a, err := netip.ParseAddr(rec.str(k)); err == nil {
				listed = append(listed, a.String())
				for _, s := range sessions {
					configured = configured || (s.IXID == ix && slices.Contains(s.Addrs, a))
				}
			}
		}
		if !configured && len(listed) > 0 {
			out = append(out, plugin.RegistryFinding{
				Kind: "pdb_ix_stale", Severity: plugin.RegistryInfo, Registry: "peeringdb",
				Subject: fmt.Sprintf("AS%d ix %d %s", asn, ix, strings.Join(listed, " ")),
				Message: fmt.Sprintf("PeeringDB lists a connection at ix %d with %s and no address in local_lan_addrs matches it", ix, strings.Join(listed, ", ")),
			})
		}
	}
	return out
}

func findIX(ixlans []object, ix int, a netip.Addr) (object, bool) {
	for _, rec := range ixlans {
		if n, _ := rec.num("ix_id"); n != ix {
			continue
		}
		for _, k := range []string{"ipaddr4", "ipaddr6"} {
			if got, err := netip.ParseAddr(rec.str(k)); err == nil && got == a {
				return rec, true
			}
		}
	}
	return nil, false
}

// contactFindings flags a network with no visible contact and contacts not
// updated for two years. Without an API key PeeringDB shows only public
// contacts, so "none" says so.
func (c *Checker) contactFindings(pocs []object, as string) []plugin.RegistryFinding {
	if len(pocs) == 0 {
		return []plugin.RegistryFinding{{
			Kind: "pdb_contact_missing", Severity: plugin.RegistryInfo, Registry: "peeringdb",
			Subject: "AS" + as + " contacts",
			Message: fmt.Sprintf("PeeringDB shows no contact for AS%s to this reader; add a public NOC or abuse contact (without an API key only public contacts are visible)", as),
		}}
	}
	var out []plugin.RegistryFinding
	for _, p := range pocs {
		updated, err := time.Parse(time.RFC3339, p.str("updated"))
		if err != nil || c.now().Sub(updated) < contactAge {
			continue
		}
		id, _ := p.num("id")
		role := p.str("role")
		out = append(out, plugin.RegistryFinding{
			Kind: "pdb_contact_old", Severity: plugin.RegistryInfo, Registry: "peeringdb",
			Subject: fmt.Sprintf("AS%s contact %d", as, id),
			Message: fmt.Sprintf("the %s contact of AS%s was last updated %s; check that it still reaches someone", role, as, updated.Format("2006-01-02")),
		})
	}
	return out
}

// Push updates one field. It re-reads the record first and refuses when the
// field no longer holds the value the diff showed.
func (c *Checker) Push(ctx context.Context, ch plugin.RegistryChange) error {
	if ch.Registry != TypeName || ch.Op != "update_field" || !slices.Contains(pushable[ch.Class], ch.Field) {
		return plugin.ErrRegistryNoPush
	}
	if c.apiKey == "" {
		return fmt.Errorf("pushing needs %s", lookup.APIKeyEnv)
	}
	id, err := strconv.Atoi(ch.Key)
	if err != nil || id <= 0 {
		return fmt.Errorf("peeringdb: bad record id %q", ch.Key)
	}
	want, err := strconv.Atoi(ch.New)
	if err != nil || want < 0 {
		return fmt.Errorf("peeringdb: bad value %q", ch.New)
	}
	path := fmt.Sprintf("/api/%s/%d", ch.Class, id)
	cur, err := c.get(ctx, path, nil)
	if err != nil {
		return err
	}
	if len(cur) != 1 {
		return fmt.Errorf("peeringdb: %s not found", path)
	}
	rec := cur[0]
	if have, ok := rec.num(ch.Field); !ok || strconv.Itoa(have) != ch.Old {
		return fmt.Errorf("peeringdb: %s changed since the scan; rescan", ch.Field)
	}
	rec[ch.Field] = json.RawMessage(strconv.Itoa(want))
	body, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := c.limit.Wait(ctx); err != nil {
		return err
	}
	u := *c.base
	u.Path += path
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), bytes.NewReader(body))
	if err != nil {
		return errors.New("peeringdb: bad url")
	}
	req.Header.Set("Content-Type", "application/json")
	_, err = c.do(req)
	return err
}
