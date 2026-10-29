// Package rpc is the wire contract and the plugin-side helper of the
// long-running "grpc" plugin type (docs/PLUGINS.md). A plugin is a
// program that implements Plugin plus the interface of its kind (Prober,
// Source, or Notifier) and calls Serve from main. Packeteer starts it,
// checks it with the gRPC health service, restarts it when it dies, and
// stops it on shutdown.
//
// There is no announcer here: an out-of-process plugin can never inject
// routes.
package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/GrandArcher/Packeteer/internal/plugins/oop"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// ProtocolVersion is the version a host and a plugin must agree on during
// the go-plugin handshake. A mismatch stops the plugin from starting.
const ProtocolVersion = 1

// Handshake is the go-plugin handshake of this protocol. The cookie only
// stops a user from running a plugin binary by hand; it is not a secret.
var Handshake = goplugin.HandshakeConfig{
	ProtocolVersion:  ProtocolVersion,
	MagicCookieKey:   "PACKETEER_PLUGIN_COOKIE",
	MagicCookieValue: "packeteer-grpc-plugin",
}

// PluginName is the key of the plugin in a go-plugin plugin set.
const PluginName = "packeteer"

const serviceName = "packeteer.plugin.v1.Plugin"

// InitRequest is what the host sends once after each process start.
type InitRequest struct {
	Kind plugin.Kind `json:"kind"`
	// Name is the instance name from the Packeteer config.
	Name string `json:"name"`
	// Config is the plugin's config block as JSON (null when absent).
	Config json.RawMessage `json:"config,omitempty"`
}

// DecodeConfig decodes the config block into v and rejects unknown fields,
// like every built-in plugin does. An absent block leaves v unchanged.
func (r InitRequest) DecodeConfig(v any) error {
	if len(r.Config) == 0 || string(r.Config) == "null" {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(r.Config))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("config: %w", err)
	}
	return nil
}

// Plugin is implemented by every gRPC plugin.
type Plugin interface {
	// Init validates the config. An error stops Packeteer from starting
	// (or, after a restart, keeps the plugin down until the next try).
	Init(ctx context.Context, req InitRequest) error
}

// Prober is implemented by a plugin that runs as a prober. It must bind to
// req.Source, and return an error rather than a 100% loss result when it
// cannot.
type Prober interface {
	Probe(ctx context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error)
}

// Source is implemented by a plugin that runs as a target source.
type Source interface {
	Targets(ctx context.Context) ([]plugin.Target, error)
}

// Notifier is implemented by a plugin that runs as a notifier. The host
// applies the notifier filters before the call.
type Notifier interface {
	Notify(ctx context.Context, e plugin.Event) error
}

// Serve runs the plugin until the host shuts it down. Call it from main.
func Serve(p Plugin) {
	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: Handshake,
		Plugins:         PluginSet(p),
		GRPCServer:      goplugin.DefaultGRPCServer,
	})
}

// PluginSet is the go-plugin plugin set of this protocol. The host passes
// nil; a plugin passes itself (Serve does).
func PluginSet(p Plugin) goplugin.PluginSet {
	return goplugin.PluginSet{PluginName: &grpcPlugin{impl: p}}
}

type grpcPlugin struct {
	goplugin.NetRPCUnsupportedPlugin
	impl Plugin
}

func (g *grpcPlugin) GRPCServer(_ *goplugin.GRPCBroker, s *grpc.Server) error {
	s.RegisterService(&serviceDesc, &server{impl: g.impl})
	return nil
}

func (g *grpcPlugin) GRPCClient(_ context.Context, _ *goplugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return &Client{conn: c}, nil
}

// ---- Wire encoding ----

func toStruct(v any) (*structpb.Struct, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return structpb.NewStruct(m)
}

func fromStruct(s *structpb.Struct, v any) error {
	b, err := json.Marshal(s.AsMap())
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// ---- Server ----

type server struct {
	impl Plugin
	// kind is set by Init; a call of another kind is refused.
	mu   sync.Mutex
	kind plugin.Kind
}

func (s *server) initialised(k plugin.Kind) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kind == k
}

var serviceDesc = grpc.ServiceDesc{
	ServiceName: serviceName,
	HandlerType: (*any)(nil),
	Methods: []grpc.MethodDesc{
		method("Init", (*server).init),
		method("Probe", (*server).probe),
		method("Targets", (*server).targets),
		method("Notify", (*server).notify),
	},
	Metadata: "plugin.proto",
}

// method adapts a typed handler to a gRPC unary handler whose messages are
// JSON objects in a Struct.
func method[Req, Resp any](name string, h func(*server, context.Context, Req) (Resp, error)) grpc.MethodDesc {
	return grpc.MethodDesc{MethodName: name, Handler: func(srv any, ctx context.Context, dec func(any) error, ic grpc.UnaryServerInterceptor) (any, error) {
		in := new(structpb.Struct)
		if err := dec(in); err != nil {
			return nil, err
		}
		call := func(ctx context.Context, req any) (any, error) {
			var r Req
			if err := fromStruct(req.(*structpb.Struct), &r); err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "%s: %v", name, err)
			}
			resp, err := h(srv.(*server), ctx, r)
			if err != nil {
				return nil, err
			}
			out, err := toStruct(resp)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "%s: %v", name, err)
			}
			return out, nil
		}
		if ic == nil {
			return call(ctx, in)
		}
		return ic(ctx, in, &grpc.UnaryServerInfo{Server: srv, FullMethod: "/" + serviceName + "/" + name}, call)
	}}
}

func (s *server) init(ctx context.Context, req InitRequest) (struct{}, error) {
	ok := false
	switch req.Kind {
	case plugin.KindProber:
		_, ok = s.impl.(Prober)
	case plugin.KindSource:
		_, ok = s.impl.(Source)
	case plugin.KindNotifier:
		_, ok = s.impl.(Notifier)
	default:
		return struct{}{}, status.Errorf(codes.InvalidArgument, "kind %q is not supported by grpc plugins", req.Kind)
	}
	if !ok {
		return struct{}{}, status.Errorf(codes.InvalidArgument, "this plugin cannot run as a %s", req.Kind)
	}
	if err := s.impl.Init(ctx, req); err != nil {
		return struct{}{}, err
	}
	s.mu.Lock()
	s.kind = req.Kind
	s.mu.Unlock()
	return struct{}{}, nil
}

func (s *server) probe(ctx context.Context, p oop.ProbeParams) (oop.ProbeResult, error) {
	pr, ok := s.impl.(Prober)
	if !ok || !s.initialised(plugin.KindProber) {
		return oop.ProbeResult{}, status.Error(codes.FailedPrecondition, "not initialised as a prober")
	}
	req, err := p.Request()
	if err != nil {
		return oop.ProbeResult{}, status.Error(codes.InvalidArgument, err.Error())
	}
	res, err := pr.Probe(ctx, req)
	if err != nil {
		return oop.ProbeResult{}, err
	}
	return oop.NewProbeResult(res), nil
}

func (s *server) targets(ctx context.Context, _ struct{}) (oop.TargetsResult, error) {
	src, ok := s.impl.(Source)
	if !ok || !s.initialised(plugin.KindSource) {
		return oop.TargetsResult{}, status.Error(codes.FailedPrecondition, "not initialised as a source")
	}
	ts, err := src.Targets(ctx)
	if err != nil {
		return oop.TargetsResult{}, err
	}
	return oop.NewTargetsResult(ts), nil
}

func (s *server) notify(ctx context.Context, e plugin.Event) (struct{}, error) {
	n, ok := s.impl.(Notifier)
	if !ok || !s.initialised(plugin.KindNotifier) {
		return struct{}{}, status.Error(codes.FailedPrecondition, "not initialised as a notifier")
	}
	return struct{}{}, n.Notify(ctx, e)
}

// ---- Client ----

// Client is the host side of a connected plugin. It implements Prober,
// Source, and Notifier; which one is usable depends on the kind the plugin
// was initialised with.
type Client struct {
	conn *grpc.ClientConn
}

func (c *Client) invoke(ctx context.Context, name string, in, out any) error {
	req, err := toStruct(in)
	if err != nil {
		return err
	}
	resp := new(structpb.Struct)
	if err := c.conn.Invoke(ctx, "/"+serviceName+"/"+name, req, resp); err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	return fromStruct(resp, out)
}

// Init sends the config.
func (c *Client) Init(ctx context.Context, req InitRequest) error {
	return c.invoke(ctx, "Init", req, nil)
}

// Probe implements Prober.
func (c *Client) Probe(ctx context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	var res oop.ProbeResult
	if err := c.invoke(ctx, "Probe", oop.NewProbeParams(req), &res); err != nil {
		return plugin.ProbeResult{}, err
	}
	return res.Result()
}

// Targets implements Source.
func (c *Client) Targets(ctx context.Context) ([]plugin.Target, error) {
	var res oop.TargetsResult
	if err := c.invoke(ctx, "Targets", struct{}{}, &res); err != nil {
		return nil, err
	}
	return res.Parse()
}

// Notify implements Notifier.
func (c *Client) Notify(ctx context.Context, e plugin.Event) error {
	return c.invoke(ctx, "Notify", e, nil)
}

// Health asks the plugin's gRPC health service whether it is serving.
func (c *Client) Health(ctx context.Context) error {
	resp, err := healthpb.NewHealthClient(c.conn).Check(ctx, &healthpb.HealthCheckRequest{Service: goplugin.GRPCServiceName})
	if err != nil {
		return err
	}
	if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		return fmt.Errorf("health: %s", resp.GetStatus())
	}
	return nil
}
