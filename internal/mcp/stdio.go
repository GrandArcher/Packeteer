package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// maxLine caps one JSON-RPC message read from stdin, as the HTTP endpoint
// caps its body.
const maxLine = MaxRequest

// bridgeTimeout bounds one forwarded request.
const bridgeTimeout = 60 * time.Second

// Bridge is the stdio transport. It reads one JSON-RPC message per line
// from in, posts it to a running controller's POST /mcp with the bearer
// token, and writes each answer as one line to out. The controller does
// every check, so the token's role and scope are what the assistant gets.
type Bridge struct {
	// URL is the controller's /mcp endpoint.
	URL string
	// Token is an API token. It is sent only as an Authorization header.
	Token string
}

// client never follows a redirect: Go would resend the Authorization
// header to the new location, past the ValidateURL check.
var client = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// ValidateURL refuses a URL that would send the token in clear text to
// another host: it must be https, or http to a loopback address.
func ValidateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || !config.SecureURL(u) {
		return errors.New("must be an https URL, or http to a loopback address, with no user info: the token is sent in every request")
	}
	return nil
}

// Run forwards messages until in ends or ctx is done.
func (b *Bridge) Run(ctx context.Context, in io.Reader, out io.Writer) error {
	r := bufio.NewReaderSize(in, 64<<10)
	for ctx.Err() == nil {
		line, err := readLine(r)
		var ans []byte
		switch {
		case errors.Is(err, errTooLong):
			ans = replyErr(nil, codeRequest, "message too long")
		case len(bytes.TrimSpace(line)) > 0:
			ans = b.forward(ctx, line)
		}
		if ans != nil {
			if _, werr := out.Write(append(ans, '\n')); werr != nil {
				return werr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil && !errors.Is(err, errTooLong) {
			return err
		}
	}
	return ctx.Err()
}

var errTooLong = errors.New("message too long")

// readLine returns the next line. A line over maxLine is skipped to its end
// and reported as errTooLong with the line empty.
func readLine(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(buf)+len(chunk) > maxLine {
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = r.ReadSlice('\n')
			}
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, err
			}
			return nil, errors.Join(errTooLong, err)
		}
		buf = append(buf, chunk...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return buf, err
	}
}

func (b *Bridge) forward(ctx context.Context, line []byte) []byte {
	var head struct {
		ID json.RawMessage `json:"id"`
	}
	_ = json.Unmarshal(line, &head)
	fail := func(msg string) []byte {
		if len(head.ID) == 0 {
			return nil
		}
		return replyErr(head.ID, codeInternal, msg)
	}
	ctx, cancel := context.WithTimeout(ctx, bridgeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.URL, bytes.NewReader(line))
	if err != nil {
		return fail("bad request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+b.Token)
	resp, err := client.Do(req)
	if err != nil {
		return fail("controller unreachable")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResult+MaxRequest))
	if err != nil {
		return fail("controller answer unreadable")
	}
	switch {
	case resp.StatusCode == http.StatusAccepted:
		return nil
	case resp.StatusCode != http.StatusOK:
		return fail(fmt.Sprintf("controller answered HTTP %d", resp.StatusCode))
	}
	return bytes.TrimSpace(body)
}
