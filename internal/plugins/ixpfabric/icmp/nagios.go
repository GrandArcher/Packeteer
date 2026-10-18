package icmp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/plugins/ixpmember/ixf"
)

// memberExportSuffix is the only member-export path this builder accepts.
// Stripping it leaves the install prefix, including a subdirectory.
const memberExportSuffix = "/api/v4/member-export/ixf/1.0"

// nagiosCustomersPrefix is the customers document on IXP Manager's external
// superuser API. That group is mounted at /admin/api/v4. The /api/v4 alias
// in the HTML docs is registered only when UNSECURED_API_ACCESS is on
// (off by default since v7.2) and this builder does not request it.
// The template suffix and every other nagios route are refused because
// this builder never adds them.
const nagiosCustomersPrefix = "/admin/api/v4/nagios/customers/"

const (
	apiKeyHeader       = "X-IXP-Manager-API-Key"
	pingServiceUse     = "ixp-manager-member-ping-service"
	pingBusyServiceUse = "ixp-manager-member-ping-busy-service"
)

// nagiosURL is GET /admin/api/v4/nagios/customers/{vlanid}/4|6 on the same
// origin as the member export. vlanid is the VLAN database id. The query
// string is dropped. family is the vantage family, not the URL segment.
func nagiosURL(memberURL string, vlan int, family string) (string, error) {
	proto, ok := familyProto(family)
	if vlan < 1 || !ok {
		return "", errors.New("can ping list: bad vlan")
	}
	u, err := url.Parse(memberURL)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Fragment != "" {
		return "", errors.New("can ping list: member url is not the IXP Manager export")
	}
	path := strings.TrimRight(u.Path, "/")
	if !strings.HasSuffix(path, memberExportSuffix) {
		return "", errors.New("can ping list: member url is not the IXP Manager export")
	}
	u.Path = strings.TrimSuffix(path, memberExportSuffix) + nagiosCustomersPrefix + strconv.Itoa(vlan) + "/" + proto
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func familyProto(family string) (string, bool) {
	switch family {
	case "ipv4":
		return "4", true
	case "ipv6":
		return "6", true
	default:
		return "", false
	}
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

// parseNagios reads IXP Manager's customers document. Can Ping is a service
// whose use is ixp-manager-member-ping-service (busy:
// ixp-manager-member-ping-busy-service). The document does not carry
// service_description or check_command; those live on templates this
// process does not fetch. A host with no ping service is not probed.
// The busy name has the normal name as a prefix, so the match is exact.
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
		out[addr] = nagiosHost{}
	}
	for _, b := range blocks {
		if b.typ != "service" {
			continue
		}
		canPing, busy := pingTemplate(b.fields["use"])
		if !canPing {
			continue
		}
		addr, ok := byName[b.fields["host_name"]]
		if !ok {
			continue
		}
		h := out[addr]
		h.canPing = true
		if busy {
			h.busy = true
		}
		out[addr] = h
	}
	return out, nil
}

func pingTemplate(use string) (canPing, busy bool) {
	switch strings.TrimSpace(use) {
	case pingBusyServiceUse:
		return true, true
	case pingServiceUse:
		return true, false
	default:
		return false, false
	}
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
