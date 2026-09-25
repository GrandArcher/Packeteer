// Package all links every built-in plugin into the binary. Import it for
// side effects: import _ "github.com/GrandArcher/Packeteer/internal/plugins/all".
package all

import (
	_ "github.com/GrandArcher/Packeteer/internal/plugins/announcer/gobgp"  // gobgp announcer
	_ "github.com/GrandArcher/Packeteer/internal/plugins/exec"             // exec prober/source/notifier
	_ "github.com/GrandArcher/Packeteer/internal/plugins/notifier/webhook" // webhook notifier
	_ "github.com/GrandArcher/Packeteer/internal/plugins/prober/fixed"     // fixed (lab) prober
	_ "github.com/GrandArcher/Packeteer/internal/plugins/prober/icmp"      // icmp prober
	_ "github.com/GrandArcher/Packeteer/internal/plugins/prober/tcp"       // tcp prober
	_ "github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"  // weighted scorer
	_ "github.com/GrandArcher/Packeteer/internal/plugins/source/flow"      // netflow/ipfix/sflow target source
	_ "github.com/GrandArcher/Packeteer/internal/plugins/source/static"    // static target source
)
