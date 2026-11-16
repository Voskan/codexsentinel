package flow

import (
	"fmt"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/ssa"
)

// Parameter sources (SourceParam) match function parameters instead of calls.
// A spec matches a parameter whose type, without pointers and type arguments,
// is the named type Package.Function. The proto.Message spec is special: it
// matches request messages of RPC server methods (see rpcServerMethod).
const (
	protoPkg     = "google.golang.org/protobuf/proto"
	protoMessage = "Message"
)

func rpcSources() []SourceSpec {
	rpc := []string{"rpc"}
	out := []SourceSpec{
		{Package: protoPkg, Function: protoMessage, Kind: SourceParam, Tags: rpc, Description: "gRPC request message"},
		{Package: "google.golang.org/grpc/metadata", Function: "FromIncomingContext", Tags: rpc, Description: "gRPC request metadata"},
		{Package: "google.golang.org/grpc/metadata", Function: "ValueFromIncomingContext", Tags: rpc, Description: "gRPC request metadata"},
	}
	for _, pkg := range []string{"connectrpc.com/connect", "github.com/bufbuild/connect-go"} {
		out = append(out,
			SourceSpec{Package: pkg, Function: "Request", Kind: SourceParam, Tags: rpc, Description: "ConnectRPC request"},
			SourceSpec{Package: pkg, Function: "ClientStream", Kind: SourceParam, Tags: rpc, Description: "ConnectRPC client stream"},
			SourceSpec{Package: pkg, Function: "BidiStream", Kind: SourceParam, Tags: rpc, Description: "ConnectRPC bidirectional stream"},
		)
	}
	return out
}

// streamSource describes messages received on a gRPC server stream.
var streamSource = &SourceSpec{Tags: []string{"rpc"}, Description: "gRPC stream message"}

// paramSources returns the parameters of fn that receive data from remote
// clients, with the matching specs. The receiver is never a source.
func (r *Registry) paramSources(fn *ssa.Function) map[*ssa.Parameter]*SourceSpec {
	specs := r.sourcesOfKind(SourceParam)
	if len(specs) == 0 || fn.Signature == nil {
		return nil
	}
	out := map[*ssa.Parameter]*SourceSpec{}
	first := 0
	if fn.Signature.Recv() != nil {
		first = 1
	}
	server := rpcServerMethod(fn)
	for _, p := range fn.Params[min(first, len(fn.Params)):] {
		for _, spec := range specs {
			if spec.Package == protoPkg && spec.Function == protoMessage {
				if server && isProtoMessage(p.Type()) {
					out[p] = spec
				}
				continue
			}
			if pkg, name := baseTypeName(p.Type()); pkg == spec.Package && name == spec.Function {
				out[p] = spec
			}
		}
	}
	return out
}

func (r *Registry) sourcesOfKind(kind SourceKind) []*SourceSpec {
	var out []*SourceSpec
	for i := range r.Sources {
		if r.Sources[i].Kind == kind {
			out = append(out, &r.Sources[i])
		}
	}
	return out
}

// baseTypeName returns the package path and name of t after removing
// pointers; for an instantiated generic type it is the generic type's name.
func baseTypeName(t types.Type) (string, string) {
	for {
		p, ok := types.Unalias(t).(*types.Pointer)
		if !ok {
			break
		}
		t = p.Elem()
	}
	n, ok := types.Unalias(t).(*types.Named)
	if !ok || n.Obj().Pkg() == nil {
		return "", ""
	}
	return n.Origin().Obj().Pkg().Path(), n.Origin().Obj().Name()
}

// rpcServerMethod reports whether fn is an exported method that serves RPCs:
// its receiver embeds a generated Unimplemented...Server or Unsafe...Server
// type, or it has the shape of a unary handler, func(ctx context.Context,
// req *pb.Request) (*pb.Response, error). Generated client methods, which
// end with a variadic ...grpc.CallOption, are excluded.
func rpcServerMethod(fn *ssa.Function) bool {
	sig := fn.Signature
	if sig.Recv() == nil || !token.IsExported(fn.Name()) {
		return false
	}
	if sig.Variadic() {
		return false
	}
	if embedsGeneratedServer(sig.Recv().Type()) {
		return true
	}
	ps, rs := sig.Params(), sig.Results()
	return ps.Len() == 2 && isContext(ps.At(0).Type()) && isProtoMessage(ps.At(1).Type()) &&
		rs.Len() == 2 && isProtoMessage(rs.At(0).Type()) && isError(rs.At(1).Type())
}

func embedsGeneratedServer(t types.Type) bool {
	if p, ok := types.Unalias(t).(*types.Pointer); ok {
		t = p.Elem()
	}
	st, ok := t.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if !f.Embedded() {
			continue
		}
		_, name := baseTypeName(f.Type())
		if (strings.HasPrefix(name, "Unimplemented") || strings.HasPrefix(name, "Unsafe")) && strings.HasSuffix(name, "Server") {
			return true
		}
	}
	return false
}

// isProtoMessage reports whether t (or a pointer to it) implements the
// proto.Message interface of either protobuf API generation.
func isProtoMessage(t types.Type) bool {
	if _, ok := t.Underlying().(*types.Interface); ok {
		return false
	}
	for _, typ := range []types.Type{t, types.NewPointer(t)} {
		for _, method := range []string{"ProtoReflect", "ProtoMessage"} {
			obj, _, _ := types.LookupFieldOrMethod(typ, false, nil, method)
			if fn, ok := obj.(*types.Func); ok {
				if sig := fn.Type().(*types.Signature); sig.Params().Len() == 0 {
					return true
				}
			}
		}
	}
	return false
}

func isContext(t types.Type) bool {
	pkg, name := baseTypeName(t)
	return pkg == "context" && name == "Context"
}

func isError(t types.Type) bool {
	n, ok := types.Unalias(t).(*types.Named)
	return ok && n.Obj().Pkg() == nil && n.Obj().Name() == "error"
}

// isServerStream reports whether t is a gRPC server-side stream: its method
// set has both RecvMsg and SendHeader, as grpc.ServerStream does.
func isServerStream(t types.Type) bool {
	ms := types.NewMethodSet(t)
	if _, ok := t.Underlying().(*types.Interface); !ok {
		ms = types.NewMethodSet(types.NewPointer(t))
	}
	return ms.Lookup(nil, "RecvMsg") != nil && ms.Lookup(nil, "SendHeader") != nil
}

// streamMessage returns the value that receives a message from a gRPC server
// stream at a call, with a description: the result of Recv() or the argument
// of RecvMsg(m). It returns nil for other calls.
func streamMessage(common *ssa.CallCommon, recv ssa.Value, args []ssa.Value, result ssa.Value) (ssa.Value, string) {
	var name string
	var recvType types.Type
	switch {
	case common.IsInvoke():
		name, recvType = common.Method.Name(), common.Value.Type()
	case recv != nil:
		if callee := common.StaticCallee(); callee != nil {
			name, recvType = callee.Name(), recv.Type()
		}
	}
	if (name != "Recv" && name != "RecvMsg") || recvType == nil || !isServerStream(recvType) {
		return nil, ""
	}
	label := fmt.Sprintf("untrusted input received by %s.%s", typeName(recvType), name)
	switch {
	case name == "Recv" && result != nil && len(args) == 0:
		return result, label
	case name == "RecvMsg" && len(args) == 1:
		return args[0], label
	}
	return nil, ""
}
