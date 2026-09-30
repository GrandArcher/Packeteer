// Package all links every built-in plugin into the binary. Import it for
// side effects: import _ "github.com/GrandArcher/Packeteer/internal/plugins/all".
package all

import (
	_ "github.com/GrandArcher/Packeteer/internal/plugins/announcer/gobgp"    // gobgp announcer
	_ "github.com/GrandArcher/Packeteer/internal/plugins/exec"               // exec prober/source/notifier
	_ "github.com/GrandArcher/Packeteer/internal/plugins/federation/mtls"    // mTLS multi-POP federation
	_ "github.com/GrandArcher/Packeteer/internal/plugins/notifier/smtp"      // smtp notifier
	_ "github.com/GrandArcher/Packeteer/internal/plugins/notifier/snmptrap"  // snmptrap notifier
	_ "github.com/GrandArcher/Packeteer/internal/plugins/notifier/webhook"   // webhook notifier
	_ "github.com/GrandArcher/Packeteer/internal/plugins/policy/maintenance" // maintenance-window policy
	_ "github.com/GrandArcher/Packeteer/internal/plugins/policy/rules"       // prefix/ASN/country routing policy
	_ "github.com/GrandArcher/Packeteer/internal/plugins/prober/fixed"       // fixed (lab) prober
	_ "github.com/GrandArcher/Packeteer/internal/plugins/prober/icmp"        // icmp prober
	_ "github.com/GrandArcher/Packeteer/internal/plugins/prober/tcp"         // tcp prober
	_ "github.com/GrandArcher/Packeteer/internal/plugins/prober/udp"         // udp prober
	_ "github.com/GrandArcher/Packeteer/internal/plugins/ribsource/bmp"      // BMP monitoring station (RIB source)
	_ "github.com/GrandArcher/Packeteer/internal/plugins/scorer/commit"      // commit scorer
	_ "github.com/GrandArcher/Packeteer/internal/plugins/scorer/cost"        // cost scorer
	_ "github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"    // weighted scorer
	_ "github.com/GrandArcher/Packeteer/internal/plugins/source/flow"        // netflow/ipfix/sflow target source
	_ "github.com/GrandArcher/Packeteer/internal/plugins/source/outage"      // AS-path and circuit outage detector
	_ "github.com/GrandArcher/Packeteer/internal/plugins/source/span"        // SPAN/mirror passive problem detector
	_ "github.com/GrandArcher/Packeteer/internal/plugins/source/static"      // static target source
	_ "github.com/GrandArcher/Packeteer/internal/plugins/source/traceroute"  // traceroute target discovery
	_ "github.com/GrandArcher/Packeteer/internal/plugins/source/vip"         // VIP prefix/ASN target source
	_ "github.com/GrandArcher/Packeteer/internal/plugins/storage/sqlite"     // sqlite history storage
	_ "github.com/GrandArcher/Packeteer/internal/plugins/telemetry/fixed"    // fixed (lab) telemetry
	_ "github.com/GrandArcher/Packeteer/internal/plugins/telemetry/snmp"     // SNMP interface telemetry
	_ "github.com/GrandArcher/Packeteer/internal/plugins/whois/rdap"         // RDAP whois (troubleshooting)
)
