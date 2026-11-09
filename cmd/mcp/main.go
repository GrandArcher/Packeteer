// Command packeteer-mcp is the stdio transport of the Packeteer MCP server
// (#302). It forwards each JSON-RPC line on stdin to a running controller's
// POST /mcp and prints the answer, so an assistant that starts MCP servers
// as subprocesses (for example: docker exec -i packeteer packeteer-mcp)
// can use the controller. All checks happen in the controller.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/GrandArcher/Packeteer/internal/mcp"
)

const defaultURL = "http://127.0.0.1:8080/mcp"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Getenv, os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, getenv func(string) string, in io.Reader, out, errOut io.Writer) int {
	url := getenv("PACKETEER_MCP_URL")
	if url == "" {
		url = defaultURL
	}
	if err := mcp.ValidateURL(url); err != nil {
		fmt.Fprintln(errOut, "packeteer-mcp: PACKETEER_MCP_URL:", err)
		return 2
	}
	token := getenv("PACKETEER_MCP_TOKEN")
	if token == "" {
		fmt.Fprintln(errOut, "packeteer-mcp: PACKETEER_MCP_TOKEN is not set: create an API token with scope mcp (see docs/mcp.md)")
		return 2
	}
	b := &mcp.Bridge{URL: url, Token: token}
	if err := b.Run(ctx, in, out); err != nil && ctx.Err() == nil {
		fmt.Fprintln(errOut, "packeteer-mcp:", err)
		return 1
	}
	return 0
}
