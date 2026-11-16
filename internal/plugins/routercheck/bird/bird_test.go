package bird

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/plugins/routercheck/readonly"
	"github.com/GrandArcher/Packeteer/internal/snippet"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var q = plugin.FilterQuery{Community: "64512:666", Packeteer: netip.MustParseAddr("192.0.2.10")}

// protocolsReply follows what BIRD 2.17 prints for show protocols all
// (proto_cmd_show, bgp_show_proto_info, channel_show_info), cut down.
func protocolsReply(packeteerIn, transitOut string) string {
	return "2002-Name       Proto      Table      State  Since         Info\n" +
		"1002-device1    Device     ---        up     01:02:03.456  \n" +
		"1006-\n" +
		"1002-packeteer  BGP        ---        start  01:02:03.456  Active        Socket: Connection refused\n" +
		"1006-  Description:    packeteer\n" +
		"   BGP state:          Active\n" +
		"     Neighbor address: 192.0.2.10\n" +
		"     Neighbor AS:      64512\n" +
		"     Local AS:         64512\n" +
		"     Last error:       Socket: Connection refused\n" +
		"   Channel ipv4\n" +
		"     State:          DOWN\n" +
		"     Table:          master4\n" +
		"     Preference:     100\n" +
		"     Input filter:   " + packeteerIn + "\n" +
		"     Output filter:  (unnamed)\n" +
		" \n" +
		"1002-transit    BGP        ---        start  01:02:03.456  Active\n" +
		"1006-  BGP state:          Active\n" +
		"     Neighbor address: 192.0.2.20\n" +
		"     Neighbor AS:      64511\n" +
		"     Local AS:         64512\n" +
		"   Channel ipv4\n" +
		"     State:          DOWN\n" +
		"     Input filter:   ACCEPT\n" +
		"     Output filter:  " + transitOut + "\n" +
		" \n" +
		"0000 \n"
}

// snippetConf is the BIRD config `packeteer -snippet bird` prints, with an
// eBGP protocol that uses its ebgp_out filter.
func snippetConf(t *testing.T, community string) string {
	t.Helper()
	out, err := snippet.Join("bird", []snippet.Params{{ASN: 64512, Router: "192.0.2.254", Packeteer: "192.0.2.10", Community: community}})
	if err != nil {
		t.Fatal(err)
	}
	return "router id 192.0.2.254;\nprotocol device {}\n" + out + `
protocol bgp transit {
	local 192.0.2.254 as 64512;
	neighbor 192.0.2.20 as 64511;
	ipv4 { import all; export filter ebgp_out; };
}
`
}

func verdicts(fs []plugin.FilterFinding) string {
	var v []string
	for _, f := range fs {
		v = append(v, string(f.Verdict))
	}
	return strings.Join(v, ",")
}

func details(fs []plugin.FilterFinding) string {
	var d []string
	for _, f := range fs {
		d = append(d, f.Detail+" | "+f.Fix)
	}
	return strings.Join(d, "\n")
}

func TestSnippetFiltersPass(t *testing.T) {
	protos := parseProtocols(lines(t, protocolsReply("packeteer_in", "ebgp_out")))
	got := check(protos, parseConfig(snippetConf(t, "64512:666")), q)
	if verdicts(got) != "pass,pass" {
		t.Fatalf("findings:\n%s", details(got))
	}
	if !strings.Contains(got[0].Detail, "protocol packeteer, ipv4): filter packeteer_in accepts only routes with 64512:666") ||
		!strings.Contains(got[1].Detail, "eBGP protocol transit (ipv4): filter ebgp_out rejects 64512:666 at statement 1") {
		t.Errorf("details:\n%s", details(got))
	}
	large := plugin.FilterQuery{Community: "65536:666:1", Packeteer: q.Packeteer}
	if got := check(protos, parseConfig(snippetConf(t, "65536:666:1")), large); verdicts(got) != "pass,pass" {
		t.Fatalf("large community:\n%s", details(got))
	}
}

// The fix text quotes the condition exactly as the bird snippet writes it.
func TestMatcherTextIsTheSnippets(t *testing.T) {
	for _, c := range []string{"64512:666", "65536:666:1"} {
		if got, want := newMatcher(c).text, (snippet.Params{Community: c}).BirdMatch(); got != want {
			t.Errorf("%s: %q, snippet writes %q", c, got, want)
		}
	}
}

func TestMissingEBGPRejectFailsWithTheFix(t *testing.T) {
	conf := strings.Replace(snippetConf(t, "64512:666"), "filter ebgp_out {", "filter ebgp_out {\n\tbgp_path.prepend(64512);", 1)
	conf = strings.Replace(conf, "filter ebgp_out {", "filter ebgp_out_old {", 1) + "\nfilter ebgp_out {\n\taccept;\n}\n"
	got := check(parseProtocols(lines(t, protocolsReply("packeteer_in", "ebgp_out"))), parseConfig(conf), q)
	if verdicts(got) != "pass,fail" {
		t.Fatalf("findings:\n%s", details(got))
	}
	for _, want := range []string{"first statement of filter ebgp_out", "if (64512, 666) ~ bgp_community then reject;", "birdc configure"} {
		if !strings.Contains(got[1].Fix, want) {
			t.Errorf("fix %q lacks %q", got[1].Fix, want)
		}
	}
}

func TestFilterCases(t *testing.T) {
	base := snippetConf(t, "64512:666")
	cases := []struct {
		name, in, out, conf, want, detail string
	}{
		{"export all", "packeteer_in", "ACCEPT", base, "pass,fail", "export all, so routes with 64512:666 are sent"},
		{"export none", "packeteer_in", "REJECT", base, "pass,pass", "export none"},
		{"import all", "ACCEPT", "ebgp_out", base, "fail,pass", "every route from Packeteer is accepted"},
		{"import none", "REJECT", "ebgp_out", base, "fail,pass", "Packeteer's routes are dropped"},
		{"inline filter", "(unnamed)", "ebgp_out", base, "unknown,pass", "unnamed (inline) filter"},
		{"filter not in the file", "packeteer_in", "other_out", base, "pass,unknown", "filter other_out is not in the config file."},
		{"filter in an include", "packeteer_in", "other_out", base + `include "/etc/bird/peers/*.conf";`, "pass,unknown", "included files are not read"},
		{"list form, comments, and strings", "pk_in", "pk_out", base + `
# filter pk_out { accept; }
filter pk_in {
	/* only Packeteer's routes { } */
	if bgp_community ~ [(64512, 666)] then accept;
	reject "not from Packeteer {";
}
filter pk_out {
	if net.len > 24 then reject;
	if ((64512,666) ~ bgp_community) then reject;
	bgp_path.prepend(64512);
	accept;
}`, "pass,pass", "rejects 64512:666 at statement 2"},
		{"import accepts on another condition", "pk_in", "ebgp_out", base + `
filter pk_in {
	if net ~ [ 198.51.100.0/24+ ] then accept;
	reject;
}`, "fail,pass", "accepts routes without 64512:666"},
		{"import accepts unconditionally", "pk_in", "ebgp_out", base + "\nfilter pk_in { accept; }", "fail,pass", "statement 1"},
		{"import never accepts", "pk_in", "ebgp_out", base + "\nfilter pk_in { if net.len > 24 then reject; reject; }", "fail,pass", "never accepts"},
		{"import on another community test", "pk_in", "ebgp_out", base + "\nfilter pk_in { if (64512, 1) ~ bgp_community then accept; reject; }", "unknown,pass", "community condition the check does not read"},
		{"export with an else", "packeteer_in", "pk_out", base + "\nfilter pk_out { if (64512,666) ~ bgp_community then reject; else accept; }", "pass,unknown", "statement 1 is not one the check reads"},
		{"export assignment first", "packeteer_in", "pk_out", base + "\nfilter pk_out { bgp_med = 10; if (64512,666) ~ bgp_community then reject; accept; }", "pass,unknown", "statement 1"},
		{"export accepts on a condition first", "packeteer_in", "pk_out", base + "\nfilter pk_out { if net ~ [ 203.0.113.0/24 ] then accept; if (64512,666) ~ bgp_community then reject; }", "pass,fail", "accepts at statement 1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := check(parseProtocols(lines(t, protocolsReply(c.in, c.out))), parseConfig(c.conf), q)
			if verdicts(got) != c.want {
				t.Fatalf("findings, want %s:\n%s", c.want, details(got))
			}
			if !strings.Contains(details(got), c.detail) {
				t.Errorf("details lack %q:\n%s", c.detail, details(got))
			}
			for _, g := range got {
				if (g.Verdict == plugin.VerdictFail) != (g.Fix != "") {
					t.Errorf("verdict %s with fix %q", g.Verdict, g.Fix)
				}
			}
		})
	}
}

// A file BIRD does not run may be half edited: no prefix of a config, cut at
// any byte, panics the parser.
func TestParseConfigCutAnywhere(t *testing.T) {
	text := snippetConf(t, "64512:666") + `
filter pk { if a then accept; else { if b then reject; } else
	/* open comment
`
	protos := parseProtocols(lines(t, protocolsReply("packeteer_in", "pk")))
	for i := range len(text) + 1 {
		cf := parseConfig(text[:i])
		_ = check(protos, cf, q)
	}
	for _, body := range []string{"if a then accept; else", "if", "if a then", "if a then accept; else if", "{", "accept", "reject \"x"} {
		_ = parseConfig("filter f { " + body)
		_ = parseConfig("filter f { " + body + " }")
	}
}

func TestProtocolCases(t *testing.T) {
	conf := parseConfig(snippetConf(t, "64512:666"))
	noPK := strings.Replace(protocolsReply("packeteer_in", "ebgp_out"), "192.0.2.10", "192.0.2.11", 1)
	got := check(parseProtocols(lines(t, noPK)), conf, q)
	if verdicts(got) != "pass,fail" || !strings.Contains(got[1].Detail, "no BGP protocol with neighbor 192.0.2.10") {
		t.Fatalf("no Packeteer protocol:\n%s", details(got))
	}
	ebgpPK := strings.Replace(protocolsReply("packeteer_in", "ebgp_out"), "Neighbor AS:      64512", "Neighbor AS:      64496", 1)
	if got := check(parseProtocols(lines(t, ebgpPK)), conf, q); verdicts(got) != "fail,pass" || !strings.Contains(got[0].Detail, "not an iBGP session") {
		t.Fatalf("eBGP Packeteer protocol:\n%s", details(got))
	}
	onlyPK := strings.Split(protocolsReply("packeteer_in", "ebgp_out"), "1002-transit")[0] + "0000 \n"
	if got := check(parseProtocols(lines(t, onlyPK)), conf, q); verdicts(got) != "pass,pass" || got[1].Detail != "BIRD has no eBGP protocol." {
		t.Fatalf("no eBGP protocol:\n%s", details(got))
	}
}

// lines reads a reply the way the session does.
func lines(t *testing.T, reply string) []line {
	t.Helper()
	s := &session{r: bufio.NewReader(strings.NewReader(reply))}
	out, code, err := s.reply()
	if err != nil || code != 0 {
		t.Fatalf("reply: code %d, %v", code, err)
	}
	return out
}

// fakeBIRD answers on a connection the way BIRD's control socket does and
// records each command it received.
type fakeBIRD struct {
	mu       sync.Mutex
	got      []string
	restrict string
}

func (f *fakeBIRD) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.got...)
}

func (f *fakeBIRD) serve(c net.Conn) {
	defer c.Close()
	if _, err := fmt.Fprint(c, "0001 BIRD 2.17.1 ready.\n"); err != nil {
		return
	}
	r := bufio.NewReader(c)
	for {
		cmd, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd = strings.TrimSuffix(cmd, "\n")
		f.mu.Lock()
		f.got = append(f.got, cmd)
		f.mu.Unlock()
		var rep string
		switch cmd {
		case "restrict":
			rep = f.restrict
		case "show protocols all":
			rep = protocolsReply("packeteer_in", "ebgp_out")
		default:
			rep = "9001 syntax error\n"
		}
		if _, err := fmt.Fprint(c, rep); err != nil {
			return
		}
	}
}

func TestNonReadCommandsAreRefused(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close() })
	f := &fakeBIRD{restrict: "0016 Access restricted\n"}
	go f.serve(server)
	s := &session{w: client, r: bufio.NewReader(client)}
	if _, code, err := s.reply(); err != nil || code != 1 {
		t.Fatalf("greeting: %d, %v", code, err)
	}
	for _, cmd := range []string{
		"configure", "configure soft", "configure check", "configure undo", "configure confirm", "reload all", "reload in packeteer",
		"disable transit", "enable packeteer", "restart all", "down", "graceful restart", "dump filter all", "dump routes",
		"eval 1", "echo all", "debug all all", "mrtdump all all", "show route", "show protocols", "show protocols all transit",
		"show protocols all\nconfigure", "restrict\nconfigure", "timeformat iso long", "", " ",
	} {
		if _, _, err := s.run(cmd); !errors.Is(err, readonly.ErrRefused) {
			t.Errorf("%q = %v, want ErrRefused", cmd, err)
		}
	}
	if got := f.commands(); len(got) != 0 {
		t.Fatalf("BIRD received %q", got)
	}
}

func TestCheckFiltersOverTheSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "lab-bird.ctl")
	conf := filepath.Join(dir, "lab-bird.conf")
	if err := os.WriteFile(conf, []byte(snippetConf(t, "64512:666")), 0o600); err != nil {
		t.Fatal(err)
	}
	env := func(k string) string {
		return map[string]string{"PK_SOCK": sock, "PK_CONF": conf}[k]
	}
	cfg, _ := plugin.ConfigFromYAML("socket_env: PK_SOCK\nconfig_env: PK_CONF")
	rc, err := New(cfg, plugin.Env{Getenv: env})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rc.CheckFilters(context.Background(), q); err == nil || strings.Contains(err.Error(), dir) || strings.Contains(err.Error(), "lab-bird") {
		t.Fatalf("no BIRD: %v", err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("no unix sockets here:", err)
	}
	defer ln.Close()
	for _, c := range []struct {
		restrict string
		want     string
	}{
		{"0016 Access restricted\n", "pass,pass"},
		{"9001 syntax error\n", ""},
	} {
		f := &fakeBIRD{restrict: c.restrict}
		go func() {
			if conn, err := ln.Accept(); err == nil {
				f.serve(conn)
			}
		}()
		got, err := rc.CheckFilters(context.Background(), q)
		if c.want == "" {
			// No restricted session, so nothing else is asked.
			if err == nil || !strings.Contains(err.Error(), "did not restrict") {
				t.Fatalf("unrestricted: %v", err)
			}
			if cmds := f.commands(); len(cmds) != 1 || cmds[0] != "restrict" {
				t.Fatalf("after a refused restrict BIRD received %q", cmds)
			}
			continue
		}
		if err != nil || verdicts(got) != c.want {
			t.Fatalf("CheckFilters = %v:\n%s", err, details(got))
		}
		if cmds := f.commands(); strings.Join(cmds, "|") != "restrict|show protocols all" {
			t.Fatalf("commands = %q", cmds)
		}
	}

	if err := os.Remove(conf); err != nil {
		t.Fatal(err)
	}
	if _, err := rc.CheckFilters(context.Background(), q); err == nil || strings.Contains(err.Error(), dir) || !strings.Contains(err.Error(), "read the BIRD config") {
		t.Fatalf("no config file: %v", err)
	}
	for _, bad := range []string{"socket_env: PK_SOCK", "config_env: PK_CONF", "socket_env: PK_SOCK\nconfig_env: PK_NONE", "socket_env: PK_SOCK\nconfig_env: PK_CONF\nextra: 1"} {
		cfg, _ := plugin.ConfigFromYAML(bad)
		if _, err := New(cfg, plugin.Env{Getenv: env}); err == nil {
			t.Errorf("New(%q) accepted", bad)
		}
	}
}

func TestReplyErrors(t *testing.T) {
	for _, bad := range []string{"garbage\n", "00x1 x\n", "1002-partial"} {
		s := &session{r: bufio.NewReader(strings.NewReader(bad))}
		if _, _, err := s.reply(); err == nil {
			t.Errorf("%q read without error", bad)
		}
	}
	s := &session{r: bufio.NewReader(strings.NewReader("+ log echo\n0016 Access restricted\n"))}
	if _, code, err := s.reply(); err != nil || code != 16 {
		t.Errorf("echo line: %d, %v", code, err)
	}
}
