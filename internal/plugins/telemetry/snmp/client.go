package snmp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// session is one poll against one agent. Close releases the socket.
type session interface {
	Get(oids []string) ([]gosnmp.SnmpPDU, error)
	Walk(oid string) ([]gosnmp.SnmpPDU, error)
	Close() error
}

type gosnmpSession struct {
	c         *gosnmp.GoSNMP
	version   string
	community string
}

func (s *gosnmpSession) Get(oids []string) ([]gosnmp.SnmpPDU, error) {
	pkt, err := s.c.Get(oids)
	if err != nil {
		return nil, err
	}
	// check rejects a v2c response whose community is not the one we
	// sent. The value is not included in the error.
	if err := s.check(pkt); err != nil {
		return nil, err
	}
	return pkt.Variables, nil
}

// Walk reads a column with GETBULK. It checks the v2c community on every
// response, which BulkWalkAll does not expose.
func (s *gosnmpSession) Walk(root string) ([]gosnmp.SnmpPDU, error) {
	if !strings.HasPrefix(root, ".") {
		root = "." + root
	}
	maxRep := s.c.MaxRepetitions
	if maxRep == 0 {
		maxRep = 10
	}
	oid := root
	var out []gosnmp.SnmpPDU
	for len(out) <= maxWalk {
		pkt, err := s.c.GetBulk([]string{oid}, 0, maxRep)
		if err != nil {
			return nil, err
		}
		if err := s.check(pkt); err != nil {
			return nil, err
		}
		if len(pkt.Variables) == 0 {
			return out, nil
		}
		for _, p := range pkt.Variables {
			if p.Type == gosnmp.EndOfMibView || p.Type == gosnmp.NoSuchObject || p.Type == gosnmp.NoSuchInstance {
				return out, nil
			}
			if !strings.HasPrefix(p.Name, root+".") {
				return out, nil
			}
			if p.Name == oid {
				return nil, fmt.Errorf("OID not increasing: %s", p.Name)
			}
			out = append(out, p)
			oid = p.Name
			if len(out) > maxWalk {
				return out, nil
			}
		}
	}
	return out, nil
}

func (s *gosnmpSession) check(pkt *gosnmp.SnmpPacket) error {
	if pkt.Error != gosnmp.NoError {
		return fmt.Errorf("snmp error %s", pkt.Error)
	}
	if s.version == "2c" && pkt.Community != s.community {
		return fmt.Errorf("response community does not match")
	}
	return nil
}

func (s *gosnmpSession) Close() error {
	if s.c == nil || s.c.Conn == nil {
		return nil
	}
	return s.c.Conn.Close()
}

// dialSNMP opens a UDP session. Cancelling ctx closes the socket so
// shutdown does not wait out a full request timeout.
func dialSNMP(ctx context.Context, h hostSpec, timeout time.Duration, retries int) (session, error) {
	g := &gosnmp.GoSNMP{
		Target:             h.address,
		Port:               h.port,
		Transport:          "udp",
		Timeout:            timeout,
		Retries:            retries,
		MaxOids:            16,
		MaxRepetitions:     10,
		Context:            ctx,
		ExponentialTimeout: false,
	}
	if err := applySecurity(g, h); err != nil {
		return nil, err
	}
	if err := g.Connect(); err != nil {
		return nil, err
	}
	go func() {
		<-ctx.Done()
		if g.Conn != nil {
			_ = g.Conn.Close()
		}
	}()
	return &gosnmpSession{c: g, version: h.version, community: h.community}, nil
}

func applySecurity(g *gosnmp.GoSNMP, h hostSpec) error {
	switch h.version {
	case "2c":
		g.Version = gosnmp.Version2c
		g.Community = h.community
		return nil
	case "3":
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		g.ContextName = h.context
		sp := &gosnmp.UsmSecurityParameters{UserName: h.username}
		switch h.level {
		case "noAuthNoPriv":
			g.MsgFlags = gosnmp.NoAuthNoPriv
			sp.AuthenticationProtocol = gosnmp.NoAuth
			sp.PrivacyProtocol = gosnmp.NoPriv
		case "authNoPriv":
			g.MsgFlags = gosnmp.AuthNoPriv
			sp.AuthenticationProtocol = authProto(h.authProto)
			sp.AuthenticationPassphrase = h.authPass
			sp.PrivacyProtocol = gosnmp.NoPriv
		case "authPriv":
			g.MsgFlags = gosnmp.AuthPriv
			sp.AuthenticationProtocol = authProto(h.authProto)
			sp.AuthenticationPassphrase = h.authPass
			sp.PrivacyProtocol = privProto(h.privProto)
			sp.PrivacyPassphrase = h.privPass
		default:
			return fmt.Errorf("security level %q", h.level)
		}
		g.SecurityParameters = sp
		return nil
	default:
		return fmt.Errorf("version %q", h.version)
	}
}

func authProto(name string) gosnmp.SnmpV3AuthProtocol {
	switch name {
	case "MD5":
		return gosnmp.MD5
	case "SHA":
		return gosnmp.SHA
	case "SHA224":
		return gosnmp.SHA224
	case "SHA256":
		return gosnmp.SHA256
	case "SHA384":
		return gosnmp.SHA384
	case "SHA512":
		return gosnmp.SHA512
	default:
		return gosnmp.NoAuth
	}
}

func privProto(name string) gosnmp.SnmpV3PrivProtocol {
	switch name {
	case "DES":
		return gosnmp.DES
	case "AES":
		return gosnmp.AES
	case "AES192":
		return gosnmp.AES192
	case "AES256":
		return gosnmp.AES256
	case "AES192C":
		return gosnmp.AES192C
	case "AES256C":
		return gosnmp.AES256C
	default:
		return gosnmp.NoPriv
	}
}
