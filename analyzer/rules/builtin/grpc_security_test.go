package builtin

import (
	"testing"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/testutil"
)

var grpcStubFiles = map[string]string{
	"go.mod":            "module example.com/fixture\n\ngo 1.24\n\nrequire google.golang.org/grpc v1.0.0\n\nreplace google.golang.org/grpc => ./stubs/grpc\n",
	"stubs/grpc/go.mod": "module google.golang.org/grpc\n\ngo 1.24\n",
	"stubs/grpc/grpc.go": `package grpc

import (
	"context"

	"google.golang.org/grpc/credentials"
)

type ClientConn struct{}
type DialOption interface{ dial() }
type ServerOption interface{ server() }
type Server struct{}
type UnaryServerInterceptor func(ctx context.Context, req any) (any, error)

type option struct{}

func (option) dial()   {}
func (option) server() {}

func NewClient(target string, opts ...DialOption) (*ClientConn, error)                      { return nil, nil }
func Dial(target string, opts ...DialOption) (*ClientConn, error)                           { return nil, nil }
func DialContext(ctx context.Context, target string, opts ...DialOption) (*ClientConn, error) { return nil, nil }
func WithInsecure() DialOption                                                              { return option{} }
func WithTransportCredentials(c credentials.TransportCredentials) DialOption                { return option{} }
func Creds(c credentials.TransportCredentials) ServerOption                                 { return option{} }
func NewServer(opts ...ServerOption) *Server                                                { return nil }
func MaxRecvMsgSize(n int) ServerOption                                                     { return option{} }
func MaxConcurrentStreams(n uint32) ServerOption                                            { return option{} }
func UnaryInterceptor(i UnaryServerInterceptor) ServerOption                                { return option{} }
`,
	"stubs/grpc/credentials/credentials.go": `package credentials

import "crypto/tls"

type TransportCredentials interface{ Info() string }

type tlsCreds struct{}

func (tlsCreds) Info() string { return "tls" }

func NewTLS(c *tls.Config) TransportCredentials { return tlsCreds{} }
`,
	"stubs/grpc/credentials/insecure/insecure.go": `package insecure

import "google.golang.org/grpc/credentials"

type creds struct{}

func (creds) Info() string { return "insecure" }

func NewCredentials() credentials.TransportCredentials { return creds{} }
`,
}

func grpcFiles(app string) map[string]string {
	files := map[string]string{"app/app.go": app}
	for name, src := range grpcStubFiles {
		files[name] = src
	}
	return files
}

func registerGRPC(ctx *analyzer.AnalyzerContext) { RegisterGRPCSecurityRules(ctx) }

func TestGRPCInsecureCredentials(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, grpcFiles(`package app

import (
	"context"
	"crypto/tls"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const localAddr = "localhost:50051"

func prod() (*grpc.ClientConn, error) {
	return grpc.NewClient("api.prod.internal:443", grpc.WithTransportCredentials(insecure.NewCredentials())) // want "grpc-insecure-credentials"
}

func legacy(ctx context.Context, addr string) (*grpc.ClientConn, error) {
	return grpc.DialContext(ctx, addr, grpc.WithInsecure()) // want "grpc-insecure-credentials"
}

func local() (*grpc.ClientConn, error) {
	return grpc.NewClient(localAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
}

func loopback() (*grpc.ClientConn, error) {
	return grpc.Dial("127.0.0.1:9000", grpc.WithTransportCredentials(insecure.NewCredentials()))
}

func inMemory() (*grpc.ClientConn, error) {
	return grpc.NewClient("passthrough:///bufnet", grpc.WithTransportCredentials(insecure.NewCredentials()))
}

func socket() (*grpc.ClientConn, error) {
	return grpc.NewClient("unix:///run/app.sock", grpc.WithTransportCredentials(insecure.NewCredentials()))
}

func secure() (*grpc.ClientConn, error) {
	return grpc.NewClient("api.prod.internal:443", grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})))
}

func options() []grpc.DialOption {
	return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())} // want "grpc-insecure-credentials"
}
`), registerGRPC)
}

func TestGRPCServerLimits(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, grpcFiles(`package app

import (
	"context"

	"google.golang.org/grpc"
)

func auth(ctx context.Context, req any) (any, error) { return req, nil }

func bare() *grpc.Server {
	return grpc.NewServer() // want "grpc-server-missing-limits:no MaxConcurrentStreams"
}

func huge() *grpc.Server {
	return grpc.NewServer(grpc.MaxRecvMsgSize(512<<20), grpc.MaxConcurrentStreams(100)) // want "grpc-server-missing-limits:512 MiB"
}

func limited() *grpc.Server {
	return grpc.NewServer(grpc.MaxRecvMsgSize(8<<20), grpc.MaxConcurrentStreams(100))
}

func intercepted() *grpc.Server {
	opts := []grpc.ServerOption{grpc.UnaryInterceptor(auth)}
	opts = append(opts, grpc.MaxRecvMsgSize(4<<20))
	return grpc.NewServer(opts...)
}

func fromConfig(opts []grpc.ServerOption) *grpc.Server {
	return grpc.NewServer(opts...)
}

func external() *grpc.Server {
	return grpc.NewServer(serverOpts()...)
}

func serverOpts() []grpc.ServerOption { return nil }
`), registerGRPC)
}

func TestSSRFMissingIPGuard(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, map[string]string{"app/app.go": `package app

import (
	"context"
	"net"
	"net/http"
	"syscall"
	"time"
)

type Notifier struct {
	client *http.Client
}

func NewNotifier() *Notifier {
	return &Notifier{client: &http.Client{Transport: &http.Transport{MaxIdleConns: 10}}} // want "ssrf-missing-ip-guard"
}

func (n *Notifier) Send(ctx context.Context, hookURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hookURL, nil)
	if err != nil {
		return err
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

var plainDialer = &net.Dialer{Timeout: 5 * time.Second}

var fetcher = &http.Client{Transport: &http.Transport{DialContext: plainDialer.DialContext}} // want "ssrf-missing-ip-guard"

func Fetch(target string) error {
	resp, err := fetcher.Get(target)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func deny(network, address string, c syscall.RawConn) error { return nil }

var guarded = &http.Client{Transport: &http.Transport{DialContext: (&net.Dialer{Control: deny}).DialContext}}

func FetchGuarded(target string) error {
	resp, err := guarded.Get(target)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

var internal = &http.Client{Transport: &http.Transport{}}

func Health() error {
	resp, err := internal.Get("https://status.example.com/health")
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func Profile(user string) error {
	resp, err := internal.Get("https://api.example.com/users/" + user)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}
`}, registerGRPC)
}
