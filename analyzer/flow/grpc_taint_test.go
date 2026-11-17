package flow_test

import (
	"strings"
	"testing"

	"github.com/Voskan/codexsentinel/v2/analyzer/flow"
	"github.com/Voskan/codexsentinel/v2/analyzer/testutil"
)

const rpcGoMod = `module example.com/fixture

go 1.24

require (
	connectrpc.com/connect v1.0.0
	google.golang.org/grpc v1.0.0
)

replace connectrpc.com/connect => ./stubs/connect

replace google.golang.org/grpc => ./stubs/grpc
`

var rpcStubs = map[string]string{
	"stubs/grpc/go.mod": "module google.golang.org/grpc\n\ngo 1.24\n",
	"stubs/grpc/grpc.go": `package grpc

import "context"

type ServerStream interface {
	SetHeader(map[string][]string) error
	SendHeader(map[string][]string) error
	Context() context.Context
	SendMsg(m any) error
	RecvMsg(m any) error
}

type CallOption interface{}
`,
	"stubs/grpc/metadata/metadata.go": `package metadata

import "context"

type MD map[string][]string

func (md MD) Get(k string) []string { return md[k] }

func FromIncomingContext(ctx context.Context) (MD, bool) { return nil, false }
`,
	"stubs/connect/go.mod": "module connectrpc.com/connect\n\ngo 1.24\n",
	"stubs/connect/connect.go": `package connect

import "net/http"

type Request[T any] struct {
	Msg    *T
	header http.Header
}

func (r *Request[T]) Header() http.Header { return r.header }

type Response[T any] struct{ Msg *T }

func NewResponse[T any](msg *T) *Response[T] { return &Response[T]{Msg: msg} }
`,
	"pb/pb.go": `package pb

import (
	"context"

	"google.golang.org/grpc"
)

type Message interface{ ProtoReflect() Message }

type GetUserRequest struct{ Filter string }

func (x *GetUserRequest) ProtoReflect() Message { return x }

func (x *GetUserRequest) GetFilter() string {
	if x != nil {
		return x.Filter
	}
	return ""
}

type UserResponse struct{ Name string }

func (x *UserResponse) ProtoReflect() Message { return x }

type UserServiceServer interface {
	GetUser(context.Context, *GetUserRequest) (*UserResponse, error)
	Chat(UserService_ChatServer) error
}

type UnimplementedUserServiceServer struct{}

func (UnimplementedUserServiceServer) GetUser(context.Context, *GetUserRequest) (*UserResponse, error) {
	return nil, nil
}

func (UnimplementedUserServiceServer) Chat(UserService_ChatServer) error { return nil }

type UserService_ChatServer interface {
	Send(*UserResponse) error
	Recv() (*GetUserRequest, error)
	grpc.ServerStream
}

type UserServiceClient interface {
	GetUser(ctx context.Context, in *GetUserRequest, opts ...grpc.CallOption) (*UserResponse, error)
}
`,
}

func rpcFixture(extra map[string]string) map[string]string {
	files := map[string]string{"go.mod": rpcGoMod}
	for name, src := range rpcStubs {
		files[name] = src
	}
	for name, src := range extra {
		files[name] = src
	}
	return files
}

const repoSrc = `package repo

import (
	"context"
	"database/sql"
)

type Repo struct{ DB *sql.DB }

func (r *Repo) Find(ctx context.Context, filter string) error {
	_, err := r.DB.QueryContext(ctx, "SELECT * FROM users WHERE "+filter) // want "sql-injection"
	return err
}

func (r *Repo) FindSafe(ctx context.Context, filter string) error {
	_, err := r.DB.QueryContext(ctx, "SELECT * FROM users WHERE name = $1", filter)
	return err
}
`

func TestGRPCHandlerRequestReachesSQLSink(t *testing.T) {
	files := rpcFixture(map[string]string{"repo/repo.go": repoSrc, "server/server.go": `package server

import (
	"context"

	"example.com/fixture/pb"
	"example.com/fixture/repo"
)

type UserServer struct {
	pb.UnimplementedUserServiceServer
	Repo *repo.Repo
}

func (s *UserServer) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.UserResponse, error) {
	if err := s.Repo.Find(ctx, req.GetFilter()); err != nil {
		return nil, err
	}
	return &pb.UserResponse{}, s.Repo.FindSafe(ctx, req.Filter)
}
`})
	issues := testutil.RunTaintOnFiles(t, files, flow.DefaultRegistry(), flow.Options{Interprocedural: true})
	if len(issues) != 1 {
		t.Fatalf("want one finding, got %+v", issues)
	}
	var trace []string
	for _, step := range issues[0].Trace {
		trace = append(trace, step.Kind+" "+step.Location.File+" "+step.Message)
	}
	joined := strings.Join(trace, "\n")
	for _, want := range []string{"source server/server.go untrusted input received by UserServer.GetUser as parameter req", "sink repo/repo.go"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("trace lacks %q:\n%s", want, joined)
		}
	}
}

func TestGRPCStreamsAndMetadata(t *testing.T) {
	files := rpcFixture(map[string]string{"server/server.go": `package server

import (
	"context"
	"database/sql"

	"example.com/fixture/pb"
	"google.golang.org/grpc/metadata"
)

type ChatServer struct {
	pb.UnimplementedUserServiceServer
	DB *sql.DB
}

func (s *ChatServer) Chat(stream pb.UserService_ChatServer) error {
	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		s.DB.Exec("DELETE FROM chat WHERE id = " + msg.Filter) // want "sql-injection"
	}
}

func Tenant(ctx context.Context, db *sql.DB) {
	md, _ := metadata.FromIncomingContext(ctx)
	db.Exec("SET tenant = " + md.Get("tenant")[0]) // want "sql-injection"
}
`})
	testutil.RunTaintBothModes(t, files, flow.DefaultRegistry())
}

func TestConnectRequestReachesSink(t *testing.T) {
	files := rpcFixture(map[string]string{"server/server.go": `package server

import (
	"context"
	"database/sql"
	"os/exec"

	"connectrpc.com/connect"
	"example.com/fixture/pb"
)

type Service struct{ DB *sql.DB }

func (s *Service) GetUser(ctx context.Context, req *connect.Request[pb.GetUserRequest]) (*connect.Response[pb.UserResponse], error) {
	_, err := s.DB.QueryContext(ctx, "SELECT * FROM users WHERE "+req.Msg.Filter) // want "sql-injection"
	_ = exec.Command("sh", "-c", req.Header().Get("X-Cmd")).Run()          // want "command-injection"
	return connect.NewResponse(&pb.UserResponse{}), err
}
`})
	testutil.RunTaintBothModes(t, files, flow.DefaultRegistry())
}

func TestNonRPCProtoParametersAreNotSources(t *testing.T) {
	files := rpcFixture(map[string]string{"store/store.go": `package store

import (
	"context"
	"database/sql"

	"example.com/fixture/pb"
	"google.golang.org/grpc"
)

type Store struct{ DB *sql.DB }

// Save takes a message built by this program; it is not an RPC handler.
func (s *Store) Save(req *pb.GetUserRequest) error {
	_, err := s.DB.Exec("INSERT INTO users VALUES ('" + req.Filter + "')")
	return err
}

type client struct{ DB *sql.DB }

// GetUser has the shape of a generated client method.
func (c *client) GetUser(ctx context.Context, in *pb.GetUserRequest, opts ...grpc.CallOption) (*pb.UserResponse, error) {
	_, err := c.DB.ExecContext(ctx, "SELECT "+in.Filter)
	return nil, err
}

func lookup(ctx context.Context, req *pb.GetUserRequest) (*pb.UserResponse, error) {
	_, err := sql.OpenDB(nil).QueryContext(ctx, "SELECT "+req.Filter)
	return nil, err
}

var _ = lookup
`})
	testutil.RunTaintBothModes(t, files, flow.DefaultRegistry())
}
