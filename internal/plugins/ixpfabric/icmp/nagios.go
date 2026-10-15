package icmp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/ixpmember/ixf"
)

// nagiosCustomers is the only IXP Manager path besides the member export
// that this process GETs. It is the document that carries Can Ping and
// Busy Host. The template suffix and every other nagios route are refused
// because this builder never adds them.
const nagiosSuffix = "/member-export/ixf/1.0"

const apiKeyHeader = "X-IXP-Manager-API-Key"

var checkPing = regexp.MustCompile(`check_ping!([0-9]+(?:\.[0-9]+)?),([0-9]+(?:\.[0-9]+)?)%!([0-9]+(?:\.[0-9]+)?),([0-9]+(?:\.[0-9]+)?)%`)

// nagiosURL is GET /api/v4/nagios/customers/{vlan}/{ipv4|ipv6} on the same
// origin as the member export, including a subdirectory install. The query
// string is dropped. vlan is the IX-F vlan id, which is IXP Manager's VLAN
// database id.
func nagiosURL(memberURL string, vlan int, family string) (string, error) {
	if vlan < 1 || (family != "ipv4" && family != "ipv6") {
		return "", errors.New("can ping list: bad vlan")
	}
	u, err := url.Parse(memberURL)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Fragment != "" {
		return "", errors.New("can ping list: member url is not the IXP Manager export")
	}
	path := strings.TrimRight(u.Path, "/")
	if !strings.HasSuffix(path, nagiosSuffix) {
		return "", errors.New("can ping list: member url is not the IXP Manager export")
	}
	u.Path = strings.TrimSuffix(path, nagiosSuffix) + "/nagios/customers/" + strconv.Itoa(vlan) + "/" + family
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func (r *runner) getNagios(ctx context.Context, raw string) ([]byte, error) {
	if r.apiKey != "" && urlHasKey(raw, r.apiKey) {
		return nil, errors.New("can ping list: url must not contain the API key")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, errors.New("can ping list: bad url")
	}
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("User-Agent", "packeteer")
	if r.apiKey != "" {
		req.Header.Set(apiKeyHeader, r.apiKey)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		if errors.Is(err, errNoRedirect) {
			return nil, errors.New("can ping list: redirects are not followed")
		}
		return nil, errors.New("can ping list: " + ixf.Redact(err.Error(), r.apiKey))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("can ping list: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, nagiosMaxBytes+1))
	if err != nil {
		return nil, errors.New("can ping list: read failed")
	}
	if len(body) > nagiosMaxBytes {
		return nil, errors.New("can ping list: response exceeds max_bytes")
	}
	if looksLikeHTML(body) {
		return nil, errors.New("can ping list: response was not a nagios config")
	}
	return body, nil
}

func urlHasKey(raw, key string) bool {
	if key == "" {
		return false
	}
	if strings.Contains(raw, key) {
		return true
	}
	esc := url.QueryEscape(key)
	return esc != key && strings.Contains(raw, esc)
}

func looksLikeHTML(body []byte) bool {
	low := bytes.ToLower(body)
	return bytes.Contains(low, []byte("<html")) || bytes.Contains(low, []byte("<!doctype"))
}

// parseNagios reads IXP Manager's customer Nagios config. A host with no
// PING service has Can Ping off. PING-Busy is the busy-host tolerance.
// The check_command warning values are that host's tolerance.
func parseNagios(body []byte) (map[string]nagiosHost, error) {
	if looksLikeHTML(body) {
		return nil, errors.New("can ping list: response was not a nagios config")
	}
	blocks := nagiosBlocks(string(body))
	byName := map[string]string{}
	for _, b := range blocks {
		if b.typ != "host" {
			continue
		}
		name := b.fields["host_name"]
		raw := b.fields["address"]
		addr, err := netip.ParseAddr(raw)
		if err != nil || addr.Zone() != "" || name == "" {
			continue
		}
		byName[name] = addr.Unmap().String()
	}
	out := make(map[string]nagiosHost, len(byName))
	for _, addr := range byName {
		out[addr] = nagiosHost{canPing: false}
	}
	for _, b := range blocks {
		if b.typ != "service" {
			continue
		}
		desc := b.fields["service_description"]
		if desc != "PING" && desc != "PING-Busy" {
			continue
		}
		addr, ok := byName[b.fields["host_name"]]
		if !ok {
			continue
		}
		h := out[addr]
		h.canPing = true
		if desc == "PING-Busy" {
			h.busy = true
		}
		if tol, ok := parseCheck(b.fields["check_command"]); ok && (desc == "PING-Busy" || !h.haveTol) {
			h.tol = tol
			h.haveTol = true
		}
		out[addr] = h
	}
	return out, nil
}

type nagiosBlock struct {
	typ    string
	fields map[string]string
}

func nagiosBlocks(text string) []nagiosBlock {
	lines := strings.Split(text, "\n")
	var out []nagiosBlock
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(line, "define ") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "define "))
		rest = strings.TrimSuffix(rest, "{")
		typ := strings.TrimSpace(rest)
		fields := map[string]string{}
		for i+1 < len(lines) {
			i++
			l := strings.TrimSpace(lines[i])
			if l == "}" {
				break
			}
			if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, ";") {
				continue
			}
			k, v, ok := cutField(l)
			if ok {
				fields[k] = v
			}
		}
		out = append(out, nagiosBlock{typ: typ, fields: fields})
	}
	return out
}

func cutField(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	i := strings.IndexAny(line, " \t")
	if i <= 0 {
		return "", "", false
	}
	return line[:i], strings.TrimSpace(line[i:]), true
}

func parseCheck(s string) (tolerance, bool) {
	m := checkPing.FindStringSubmatch(s)
	if m == nil {
		return tolerance{}, false
	}
	warnRTT, err1 := strconv.ParseFloat(m[1], 64)
	warnLoss, err2 := strconv.ParseFloat(m[2], 64)
	critRTT, err3 := strconv.ParseFloat(m[3], 64)
	if err1 != nil || err2 != nil || err3 != nil || warnRTT < 0 || warnLoss < 0 || warnLoss > 100 || critRTT < 0 {
		return tolerance{}, false
	}
	return tolerance{
		warnRTT:  time.Duration(math.Round(warnRTT * float64(time.Millisecond))),
		warnLoss: warnLoss,
		critRTT:  time.Duration(math.Round(critRTT * float64(time.Millisecond))),
	}, true
}
