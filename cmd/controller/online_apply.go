package main

import (
	"context"

	"github.com/GrandArcher/Packeteer/internal/httpapi"
	_ "github.com/GrandArcher/Packeteer/internal/plugins/all"
)

// onlineApplier builds the PUT /api/config online apply. The reload runs
// on the daemon context, the same one the SIGHUP reload uses: sources and
// policies it starts must keep running after the HTTP request ends, and a
// client disconnect must not cancel a withdraw on leaving inject. The
// request context is used only for the audit record.
func onlineApplier(daemon context.Context, reload func(context.Context) ([]string, error, error),
	after func(req context.Context, applied []string, refused, fatal error)) httpapi.OnlineApplier {
	return func(req context.Context) ([]string, error, error) {
		applied, refused, fatal := reload(daemon)
		after(req, applied, refused, fatal)
		return applied, refused, fatal
	}
}
