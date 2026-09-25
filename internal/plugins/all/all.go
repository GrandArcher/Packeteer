// Package all links every built-in plugin into the binary. Import it for
// side effects: import _ "github.com/GrandArcher/Packeteer/internal/plugins/all".
package all

import (
	_ "github.com/GrandArcher/Packeteer/internal/plugins/exec"             // exec prober/source/notifier
	_ "github.com/GrandArcher/Packeteer/internal/plugins/notifier/webhook" // webhook notifier
)
