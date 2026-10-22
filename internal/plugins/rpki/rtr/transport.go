package rtr

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// sshSubsystem is the SSH subsystem an RTR server offers (RFC 8210
// section 9.1).
const sshSubsystem = "rpki-rtr"

// TLSConfig turns on RTR over TLS (RFC 8210 section 9.2). An empty block
// verifies the server against the system roots and the address host.
type TLSConfig struct {
	// CAFile is a PEM bundle of the CAs that sign the server certificate.
	// Empty uses the system roots.
	CAFile string `yaml:"ca_file"`
	// ServerName is the name checked in the server certificate. Empty
	// uses the host of address.
	ServerName string `yaml:"server_name"`
}

// SSHConfig turns on RTR over SSH (RFC 8210 section 9.1): public-key
// login, and the server's host key must be in known_hosts.
type SSHConfig struct {
	User string `yaml:"user"`
	// KeyFile is an unencrypted private key (OpenSSH or PEM format).
	KeyFile string `yaml:"key_file"`
	// KnownHosts is an OpenSSH known_hosts file holding the server's key.
	KnownHosts string `yaml:"known_hosts"`
}

// transport dials one RTR connection: plain TCP, TLS, or SSH.
type transport struct {
	address string
	timeout time.Duration
	tls     *tls.Config
	ssh     *ssh.ClientConfig
}

// newTransport reads the TLS or SSH files once at load time, so a missing
// or bad file is a config error instead of a retry loop.
func newTransport(cfg Config) (transport, error) {
	t := transport{address: cfg.Address, timeout: cfg.Timeout}
	if cfg.TLS != nil && cfg.SSH != nil {
		return t, errors.New("set tls or ssh, not both")
	}
	if c := cfg.TLS; c != nil {
		host, _, _ := net.SplitHostPort(cfg.Address)
		tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
		if s := strings.TrimSpace(c.ServerName); s != "" {
			tc.ServerName = s
		}
		if c.CAFile != "" {
			pem, err := os.ReadFile(c.CAFile)
			if err != nil {
				return t, fmt.Errorf("tls.ca_file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return t, fmt.Errorf("tls.ca_file %s holds no PEM certificate", c.CAFile)
			}
			tc.RootCAs = pool
		}
		t.tls = tc
	}
	if c := cfg.SSH; c != nil {
		if strings.TrimSpace(c.User) == "" || c.KeyFile == "" || c.KnownHosts == "" {
			return t, errors.New("ssh needs user, key_file, and known_hosts")
		}
		key, err := os.ReadFile(c.KeyFile)
		if err != nil {
			return t, fmt.Errorf("ssh.key_file: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return t, fmt.Errorf("ssh.key_file: %w", err)
		}
		hostKey, err := knownhosts.New(c.KnownHosts)
		if err != nil {
			return t, fmt.Errorf("ssh.known_hosts: %w", err)
		}
		t.ssh = &ssh.ClientConfig{
			User:            strings.TrimSpace(c.User),
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: hostKey,
			Timeout:         cfg.Timeout,
		}
	}
	return t, nil
}

// dial opens the connection and finishes the TLS or SSH handshake within
// the timeout.
func (t transport) dial(ctx context.Context) (io.ReadWriteCloser, error) {
	d := net.Dialer{Timeout: t.timeout}
	conn, err := d.DialContext(ctx, "tcp", t.address)
	if err != nil {
		return nil, err
	}
	switch {
	case t.tls != nil:
		hctx, cancel := context.WithTimeout(ctx, t.timeout)
		defer cancel()
		tc := tls.Client(conn, t.tls)
		if err := tc.HandshakeContext(hctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return tc, nil
	case t.ssh != nil:
		s, err := sshStream(conn, t.address, t.ssh, t.timeout)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		return s, nil
	}
	return conn, nil
}

// sshRTR is the rpki-rtr subsystem's stdin and stdout on one SSH client.
type sshRTR struct {
	client *ssh.Client
	in     io.WriteCloser
	out    io.Reader
}

func (s *sshRTR) Read(p []byte) (int, error)  { return s.out.Read(p) }
func (s *sshRTR) Write(p []byte) (int, error) { return s.in.Write(p) }
func (s *sshRTR) Close() error                { return s.client.Close() }

func sshStream(conn net.Conn, addr string, cfg *ssh.ClientConfig, timeout time.Duration) (*sshRTR, error) {
	// The deadline bounds the handshake only. It is cleared before the
	// session runs: a read timeout on the raw connection would kill the
	// SSH transport, so the session loop times reads itself.
	_ = conn.SetDeadline(time.Now().Add(timeout))
	cc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		return nil, err
	}
	client := ssh.NewClient(cc, chans, reqs)
	sess, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	in, err := sess.StdinPipe()
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	out, err := sess.StdoutPipe()
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	if err := sess.RequestSubsystem(sshSubsystem); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("rtr: ssh subsystem %s: %w", sshSubsystem, err)
	}
	_ = conn.SetDeadline(time.Time{})
	return &sshRTR{client: client, in: in, out: out}, nil
}
