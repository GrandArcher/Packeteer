package snmptrap

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// receiver is a loopback trap receiver. It returns the raw datagrams.
func receiver(t *testing.T) (*net.UDPConn, int) {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, c.LocalAddr().(*net.UDPAddr).Port
}

func read(t *testing.T, c *net.UDPConn) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 65535)
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

func newNotifier(t *testing.T, y string, env map[string]string) (plugin.Notifier, error) {
	t.Helper()
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	return plugin.Notifiers.New(TypeName, c, plugin.Env{Getenv: func(k string) string { return env[k] }})
}

var ev = plugin.NewEvent(plugin.EventProviderDown, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	"probe source for transit-a is down", map[string]string{"provider": "transit-a", "reason": "no route"})

func varbinds(p *gosnmp.SnmpPacket) map[string]any {
	m := map[string]any{}
	for _, v := range p.Variables {
		val := v.Value
		if b, ok := val.([]byte); ok {
			val = string(b)
		}
		m[strings.TrimPrefix(v.Name, ".")] = val
	}
	return m
}

func TestV2cTrap(t *testing.T) {
	c, port := receiver(t)
	env := map[string]string{"TRAP_COMMUNITY": "lab-community"}
	n, err := newNotifier(t, "address: 127.0.0.1\nport: "+strconv.Itoa(port)+"\ncommunity_env: TRAP_COMMUNITY", env)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	rx := &gosnmp.GoSNMP{Version: gosnmp.Version2c, Logger: gosnmp.NewLogger(nil)}
	p, err := rx.UnmarshalTrap(read(t, c), false)
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != gosnmp.Version2c || p.Community != "lab-community" || p.PDUType != gosnmp.SNMPv2Trap {
		t.Fatalf("packet version=%v community=%q pdu=%v", p.Version, p.Community, p.PDUType)
	}
	vb := varbinds(p)
	base := DefaultEnterpriseOID
	want := map[string]any{
		oidSnmpTrapOID:  "." + base + ".0.6",
		base + ".1.1.0": "provider.down",
		base + ".1.2.0": "critical",
		base + ".1.3.0": "probe source for transit-a is down",
		base + ".1.4.0": "2026-01-02T03:04:05Z",
		base + ".1.5.0": "provider=transit-a; reason=no route",
		base + ".1.6.0": "packeteer/provider/provider=transit-a",
	}
	for k, w := range want {
		if vb[k] != w {
			t.Errorf("%s = %v, want %v", k, vb[k], w)
		}
	}
	if _, ok := vb[oidSysUpTime].(uint32); !ok {
		t.Errorf("sysUpTime missing: %v", vb)
	}
	if p.Variables[0].Name != "."+oidSysUpTime || p.Variables[1].Name != "."+oidSnmpTrapOID {
		t.Errorf("first varbinds must be sysUpTime and snmpTrapOID: %v %v", p.Variables[0].Name, p.Variables[1].Name)
	}
}

func TestV3AuthPrivTrap(t *testing.T) {
	c, port := receiver(t)
	env := map[string]string{"TRAP_USER": "packeteer", "TRAP_AUTH": "auth-pass-123", "TRAP_PRIV": "priv-pass-456"}
	y := "address: 127.0.0.1\nport: " + strconv.Itoa(port) + "\nversion: 3\nusername_env: TRAP_USER\nauth_env: TRAP_AUTH\n" +
		"auth_protocol: SHA256\npriv_env: TRAP_PRIV\npriv_protocol: AES\nengine_id: 8000000001020304\nenterprise_oid: 1.3.6.1.4.1.32473.1"
	n, err := newNotifier(t, y, env)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	rx := &gosnmp.GoSNMP{
		Version: gosnmp.Version3, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: gosnmp.AuthPriv,
		Logger: gosnmp.NewLogger(nil),
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName: "packeteer", AuthoritativeEngineID: string([]byte{0x80, 0, 0, 0, 1, 2, 3, 4}),
			AuthenticationProtocol: gosnmp.SHA256, AuthenticationPassphrase: "auth-pass-123",
			PrivacyProtocol: gosnmp.AES, PrivacyPassphrase: "priv-pass-456",
			Logger: gosnmp.NewLogger(nil),
		},
	}
	raw := read(t, c)
	if strings.Contains(string(raw), "probe source") {
		t.Fatal("authPriv trap carried the message in cleartext")
	}
	p, err := rx.UnmarshalTrap(raw, false)
	if err != nil {
		t.Fatal(err)
	}
	vb := varbinds(p)
	if vb[oidSnmpTrapOID] != ".1.3.6.1.4.1.32473.1.0.6" || vb["1.3.6.1.4.1.32473.1.1.1.0"] != "provider.down" {
		t.Fatalf("varbinds %v", vb)
	}
}

func TestFilteredEventIsNotSent(t *testing.T) {
	c, port := receiver(t)
	n, err := newNotifier(t, "address: 127.0.0.1\nport: "+strconv.Itoa(port)+"\ncommunity_env: C\nevents: [\"bgp.*\"]", map[string]string{"C": "x"})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := c.ReadFromUDP(make([]byte, 1500)); err == nil {
		t.Fatal("filtered event was sent")
	}
}

func TestConfigValidation(t *testing.T) {
	env := map[string]string{"C": "community", "U": "user", "A": "short", "AA": "long-enough", "P": "long-enough"}
	tests := []struct{ name, yaml, want string }{
		{"no address", "community_env: C", "address is required"},
		{"bad port", "address: 192.0.2.1\nport: 0x10000\ncommunity_env: C", "port"},
		{"no community", "address: 192.0.2.1", "community_env is required"},
		{"unset community", "address: 192.0.2.1\ncommunity_env: NOPE", "NOPE is not set"},
		{"v3 field on v2c", "address: 192.0.2.1\ncommunity_env: C\nusername_env: U", "community_env only"},
		{"community on v3", "address: 192.0.2.1\nversion: 3\ncommunity_env: C", "only used with version 2c"},
		{"v3 no engine", "address: 192.0.2.1\nversion: 3\nusername_env: U\nsecurity_level: noAuthNoPriv", "engine_id"},
		{"v3 short pass", "address: 192.0.2.1\nversion: 3\nusername_env: U\nengine_id: '8000000001'\nsecurity_level: authNoPriv\nauth_env: A", "at least 8"},
		{"v3 priv on authNoPriv", "address: 192.0.2.1\nversion: 3\nusername_env: U\nengine_id: '8000000001'\nsecurity_level: authNoPriv\nauth_env: AA\npriv_env: P", "does not use privacy"},
		{"v3 bad level", "address: 192.0.2.1\nversion: 3\nusername_env: U\nengine_id: '8000000001'\nsecurity_level: max", "security_level"},
		{"v3 bad auth proto", "address: 192.0.2.1\nversion: 3\nusername_env: U\nengine_id: '8000000001'\nsecurity_level: authNoPriv\nauth_env: AA\nauth_protocol: CRC", "auth_protocol"},
		{"bad version", "address: 192.0.2.1\nversion: 1\ncommunity_env: C", "version"},
		{"bad oid", "address: 192.0.2.1\ncommunity_env: C\nenterprise_oid: 1.3.x", "enterprise_oid"},
		{"literal secret key", "address: 192.0.2.1\ncommunity: public", "field community not found"},
		{"bad filter", "address: 192.0.2.1\ncommunity_env: C\nmin_severity: loud", "min_severity"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newNotifier(t, tt.yaml, env)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
	for _, ok := range []string{
		"address: 192.0.2.1\ncommunity_env: C",
		"address: 2001:db8::1\ncommunity_env: C",
		"address: 192.0.2.1\nversion: 3\nusername_env: U\nengine_id: '0x8000000001'\nsecurity_level: noAuthNoPriv",
	} {
		if _, err := newNotifier(t, ok, env); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
}
