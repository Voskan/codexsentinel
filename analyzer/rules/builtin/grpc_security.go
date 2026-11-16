package builtin

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
)

const grpcPkg = "google.golang.org/grpc"

var (
	grpcInsecureMeta = ruleMeta{
		ID: "grpc-insecure-credentials", Title: "gRPC Connection Without Transport Security", Severity: result.SeverityHigh,
		CWE: "CWE-319", OWASP: "A04:2025", Confidence: 0.9,
		Suggestion: "Use grpc.WithTransportCredentials(credentials.NewTLS(cfg)) or credentials.NewClientTLSFromCert; keep insecure credentials for local addresses and tests.",
		References: []string{"https://cwe.mitre.org/data/definitions/319.html", "https://pkg.go.dev/google.golang.org/grpc/credentials/insecure"},
	}
	grpcLimitsMeta = ruleMeta{
		ID: "grpc-server-missing-limits", Title: "gRPC Server Without Resource Limits", Severity: result.SeverityMedium,
		CWE: "CWE-400", OWASP: "A06:2025", Confidence: 0.6,
		Suggestion: "Set grpc.MaxConcurrentStreams and keep grpc.MaxRecvMsgSize at a few MiB; add interceptors for authentication and rate limiting.",
		References: []string{"https://cwe.mitre.org/data/definitions/400.html", "https://pkg.go.dev/google.golang.org/grpc#ServerOption"},
	}
	ssrfIPGuardMeta = ruleMeta{
		ID: "ssrf-missing-ip-guard", Title: "Outbound HTTP Transport Without IP Restrictions", Severity: result.SeverityMedium,
		CWE: "CWE-918", OWASP: "A01:2025", Confidence: 0.7,
		Suggestion: "Set Transport.DialContext to a net.Dialer whose Control function rejects loopback, private, link-local (169.254.0.0/16) and metadata addresses after DNS resolution.",
		References: []string{"https://cwe.mitre.org/data/definitions/918.html", "https://pkg.go.dev/net#Dialer"},
	}
)

// maxSafeRecvMsgSize is the largest message size limit not reported.
const maxSafeRecvMsgSize = 64 << 20

// RegisterGRPCSecurityRules reports plaintext gRPC connections, gRPC servers
// without resource limits and HTTP transports that can be redirected to
// internal addresses.
func RegisterGRPCSecurityRules(ctx *analyzer.AnalyzerContext) {
	registerRules(ctx, []ruleMeta{grpcInsecureMeta, grpcLimitsMeta, ssrfIPGuardMeta}, func(r *reporter) {
		if r.wants(grpcInsecureMeta.ID) || r.wants(grpcLimitsMeta.ID) {
			for _, file := range r.pass.Files {
				for _, unit := range funcUnits(file) {
					checkGRPCUnit(r, unit)
				}
			}
		}
		if r.wants(ssrfIPGuardMeta.ID) {
			checkTransportGuards(r)
		}
	})
}

func checkGRPCUnit(r *reporter, unit funcUnit) {
	info := r.pass.TypesInfo
	assigns := assignments(info, unit.Body)
	var insecure []*ast.CallExpr
	var targets []ast.Expr
	inspectShallow(unit.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fn := calleeFunc(info, call)
		switch {
		case isFunc(fn, grpcPkg+"/credentials/insecure", "NewCredentials"), isFunc(fn, grpcPkg, "WithInsecure"):
			insecure = append(insecure, call)
		case isFunc(fn, grpcPkg, "NewClient", "Dial") && len(call.Args) > 0:
			targets = append(targets, call.Args[0])
		case isFunc(fn, grpcPkg, "DialContext") && len(call.Args) > 1:
			targets = append(targets, call.Args[1])
		case isFunc(fn, grpcPkg, "NewServer"):
			checkServerOptions(r, call, assigns)
		}
		return true
	})
	if len(insecure) == 0 || allLocalTargets(info, targets) {
		return
	}
	for _, call := range insecure {
		desc := "gRPC credentials disable transport security; requests and credentials travel in plaintext."
		if len(targets) > 0 {
			desc = "gRPC connection to a non-local address uses insecure credentials; requests and credentials travel in plaintext."
		}
		r.report(grpcInsecureMeta, call, desc)
	}
}

// allLocalTargets reports whether every dial target is a constant loopback,
// in-memory (bufconn) or Unix socket address. No targets means unknown.
func allLocalTargets(info *types.Info, targets []ast.Expr) bool {
	if len(targets) == 0 {
		return false
	}
	for _, t := range targets {
		s, ok := constString(info, t)
		if !ok || !localTarget(s) {
			return false
		}
	}
	return true
}

func localTarget(target string) bool {
	if strings.HasPrefix(target, "unix:") || strings.HasPrefix(target, "unix-abstract:") {
		return true
	}
	if i := strings.Index(target, ":///"); i >= 0 {
		target = target[i+4:]
	}
	host := target
	if strings.HasPrefix(host, "[") {
		if end := strings.Index(host, "]"); end > 0 {
			host = host[1:end]
		}
	} else if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	switch host {
	case "localhost", "::1", "bufnet", "bufconn":
		return true
	}
	return strings.HasPrefix(host, "127.") || strings.HasSuffix(host, ".localhost")
}

// checkServerOptions reports a grpc.NewServer call that allows very large
// messages, or that sets neither a stream limit nor any interceptor.
func checkServerOptions(r *reporter, call *ast.CallExpr, assigns map[types.Object][]ast.Expr) {
	info := r.pass.TypesInfo
	opts, known := serverOptions(info, call, assigns)
	limited := false
	for _, opt := range opts {
		fn := calleeFunc(info, opt)
		switch {
		case isFunc(fn, grpcPkg, "MaxRecvMsgSize") && len(opt.Args) == 1:
			if size, ok := constInt(info, opt.Args[0]); ok && size > maxSafeRecvMsgSize {
				r.reportWith(grpcLimitsMeta, opt, fmt.Sprintf("grpc.MaxRecvMsgSize allows %d MiB messages; each request can allocate that much memory.", size>>20), grpcLimitsMeta.Severity, nil)
			}
		case isFunc(fn, grpcPkg, "MaxConcurrentStreams", "UnaryInterceptor", "StreamInterceptor", "ChainUnaryInterceptor", "ChainStreamInterceptor", "InTapHandle"):
			limited = true
		case fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != grpcPkg:
			known = false // an option built elsewhere may set the limits
		}
	}
	if known && !limited {
		r.report(grpcLimitsMeta, call, "grpc.NewServer sets no MaxConcurrentStreams limit and no interceptors; a client can open an unlimited number of concurrent streams.")
	}
}

// serverOptions returns the option calls passed to grpc.NewServer, following
// a spread slice to its literal. known is false when some options cannot be
// resolved.
func serverOptions(info *types.Info, call *ast.CallExpr, assigns map[types.Object][]ast.Expr) (opts []*ast.CallExpr, known bool) {
	args := call.Args
	known = true
	if call.Ellipsis.IsValid() && len(args) > 0 {
		last := args[len(args)-1]
		args = args[:len(args)-1]
		elems, ok := sliceElems(info, last, assigns)
		if !ok {
			known = false
		}
		args = append(args, elems...)
	}
	for _, arg := range args {
		if c, ok := ast.Unparen(arg).(*ast.CallExpr); ok {
			opts = append(opts, c)
		} else {
			known = false
		}
	}
	return opts, known
}

// sliceElems resolves a slice expression to the elements of the composite
// literals and appends that build it in the current function.
func sliceElems(info *types.Info, e ast.Expr, assigns map[types.Object][]ast.Expr) ([]ast.Expr, bool) {
	switch x := ast.Unparen(e).(type) {
	case *ast.CompositeLit:
		return x.Elts, true
	case *ast.Ident:
		values := assigns[objOf(info, x)]
		if len(values) == 0 {
			return nil, false
		}
		var out []ast.Expr
		for _, v := range values {
			if c, ok := ast.Unparen(v).(*ast.CallExpr); ok {
				if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "append" && len(c.Args) > 0 {
					if _, isBuiltin := info.Uses[id].(*types.Builtin); isBuiltin {
						if root, ok := ast.Unparen(c.Args[0]).(*ast.Ident); !ok || objOf(info, root) != objOf(info, x) {
							return nil, false
						}
						if c.Ellipsis.IsValid() {
							return nil, false
						}
						out = append(out, c.Args[1:]...)
						continue
					}
				}
			}
			elems, ok := sliceElems(info, v, nil)
			if !ok {
				return nil, false
			}
			out = append(out, elems...)
		}
		return out, true
	}
	return nil, false
}

// checkTransportGuards reports http.Transport literals without an IP-checking
// dialer when a client using them sends requests to non-constant URLs.
func checkTransportGuards(r *reporter) {
	info := r.pass.TypesInfo
	transports := map[*ast.CompositeLit]types.Object{} // unguarded transport -> client holder
	dynamic := map[types.Object]bool{}
	for _, file := range r.pass.Files {
		holders := clientHolders(info, file)
		for _, unit := range funcUnits(file) {
			assigns := assignments(info, unit.Body)
			collectDynamicRequests(info, unit, assigns, dynamic)
		}
		for lit, holder := range holders {
			if !transportGuarded(info, lit, file) {
				transports[lit] = holder
			}
		}
	}
	for lit, holder := range transports {
		if holder != nil && dynamic[holder] {
			r.report(ssrfIPGuardMeta, lit, fmt.Sprintf("http.Transport of %s sends requests to non-constant URLs but does not check the IP addresses it connects to; DNS rebinding can reach internal services such as 169.254.169.254.", holder.Name()))
		}
	}
}

// clientHolders maps every http.Transport literal that becomes the Transport
// of an http.Client to the variable, field or function holding that client.
func clientHolders(info *types.Info, file *ast.File) map[*ast.CompositeLit]types.Object {
	out := map[*ast.CompositeLit]types.Object{}
	transportVars := map[types.Object]*ast.CompositeLit{}
	ast.Inspect(file, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range s.Lhs {
				if i < len(s.Rhs) {
					if lit := transportLit(info, s.Rhs[i]); lit != nil {
						transportVars[objOf(info, lhs)] = lit
					}
				}
			}
		case *ast.ValueSpec:
			for i, name := range s.Names {
				if i < len(s.Values) {
					if lit := transportLit(info, s.Values[i]); lit != nil {
						transportVars[info.Defs[name]] = lit
					}
				}
			}
		}
		return true
	})
	resolve := func(e ast.Expr) *ast.CompositeLit {
		if lit := transportLit(info, e); lit != nil {
			return lit
		}
		if obj := objOf(info, e); obj != nil {
			return transportVars[obj]
		}
		return nil
	}
	var stack []ast.Node
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		switch x := n.(type) {
		case *ast.CompositeLit:
			if !typeIs(typeOf(info, x), "net/http", "Client") {
				return true
			}
			for _, elt := range x.Elts {
				if kv, ok := elt.(*ast.KeyValueExpr); ok && exprName(kv.Key) == "Transport" {
					if lit := resolve(kv.Value); lit != nil {
						out[lit] = holderOf(info, stack)
					}
				}
			}
		case *ast.AssignStmt:
			for i, lhs := range x.Lhs {
				sel, ok := lhs.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Transport" || i >= len(x.Rhs) || !typeIs(typeOf(info, sel.X), "net/http", "Client") {
					continue
				}
				if lit := resolve(x.Rhs[i]); lit != nil {
					out[lit] = objOf(info, sel.X)
				}
			}
		}
		return true
	})
	return out
}

func transportLit(info *types.Info, e ast.Expr) *ast.CompositeLit {
	e = ast.Unparen(e)
	if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.AND {
		e = ast.Unparen(u.X)
	}
	lit, ok := e.(*ast.CompositeLit)
	if !ok || !typeIs(typeOf(info, lit), "net/http", "Transport") {
		return nil
	}
	return lit
}

// holderOf finds what holds the client literal at the top of stack: the
// variable or field it is assigned to, the field of an enclosing struct
// literal, or the function returning it.
func holderOf(info *types.Info, stack []ast.Node) types.Object {
	for i := len(stack) - 2; i >= 0; i-- {
		switch p := stack[i].(type) {
		case *ast.UnaryExpr, *ast.ParenExpr:
			continue
		case *ast.AssignStmt:
			for j, rhs := range p.Rhs {
				if containsNode(rhs, stack[i+1]) && j < len(p.Lhs) {
					return objOf(info, p.Lhs[j])
				}
			}
			return nil
		case *ast.ValueSpec:
			for j, v := range p.Values {
				if containsNode(v, stack[i+1]) && j < len(p.Names) {
					return info.Defs[p.Names[j]]
				}
			}
			return nil
		case *ast.KeyValueExpr:
			if id, ok := p.Key.(*ast.Ident); ok {
				return info.Uses[id]
			}
			return nil
		case *ast.ReturnStmt:
			for k := i - 1; k >= 0; k-- {
				if fd, ok := stack[k].(*ast.FuncDecl); ok {
					return info.Defs[fd.Name]
				}
				if _, ok := stack[k].(*ast.FuncLit); ok {
					return nil
				}
			}
			return nil
		default:
			return nil
		}
	}
	return nil
}

func containsNode(root, n ast.Node) bool {
	return root.Pos() <= n.Pos() && n.End() <= root.End()
}

// transportGuarded reports whether the transport sets a dialer that may check
// the destination address. Only a net.Dialer without Control or
// ControlContext is known not to.
func transportGuarded(info *types.Info, lit *ast.CompositeLit, file *ast.File) bool {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		switch exprName(kv.Key) {
		case "DialContext", "Dial", "DialTLSContext", "DialTLS":
			sel, ok := ast.Unparen(kv.Value).(*ast.SelectorExpr)
			if !ok || !typeIs(typeOf(info, sel.X), "net", "Dialer") {
				return true
			}
			dialer := dialerLit(info, sel.X, file)
			return dialer == nil || dialerControls(dialer)
		}
	}
	return false
}

func dialerLit(info *types.Info, e ast.Expr, file *ast.File) *ast.CompositeLit {
	e = ast.Unparen(e)
	if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.AND {
		e = ast.Unparen(u.X)
	}
	if lit, ok := e.(*ast.CompositeLit); ok {
		return lit
	}
	obj := objOf(info, e)
	if obj == nil {
		return nil
	}
	values := assignments(info, file)[obj]
	if len(values) != 1 {
		return nil
	}
	return dialerLit(info, values[0], file)
}

func dialerControls(lit *ast.CompositeLit) bool {
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if name := exprName(kv.Key); name == "Control" || name == "ControlContext" {
				return true
			}
		}
	}
	return false
}

// collectDynamicRequests records the clients that send requests to URLs
// without a constant scheme and host in unit.
func collectDynamicRequests(info *types.Info, unit funcUnit, assigns map[types.Object][]ast.Expr, dynamic map[types.Object]bool) {
	inspectShallow(unit.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !ok {
			return true
		}
		fn := calleeFunc(info, call)
		var url ast.Expr
		switch {
		case isMethod(fn, "net/http", "Client", "Get", "Head", "Post", "PostForm") && len(call.Args) > 0:
			url = call.Args[0]
		case isMethod(fn, "net/http", "Client", "Do") && len(call.Args) == 1:
			url = requestURL(info, call.Args[0], assigns)
		default:
			return true
		}
		if url == nil || isConst(info, url) || hasFixedHost(info, url, assigns, 0) {
			return true
		}
		if holder := clientObject(info, sel.X, assigns); holder != nil {
			dynamic[holder] = true
		}
		return true
	})
}

// requestURL returns the URL argument of the http.NewRequest call that built
// req in the current function, or nil.
func requestURL(info *types.Info, req ast.Expr, assigns map[types.Object][]ast.Expr) ast.Expr {
	values := assigns[objOf(info, ast.Unparen(req))]
	if len(values) != 1 {
		return nil
	}
	call, ok := ast.Unparen(values[0]).(*ast.CallExpr)
	if !ok {
		return nil
	}
	idx := ssrfURLArg(calleeFunc(info, call))
	if idx < 1 || idx >= len(call.Args) {
		return nil
	}
	return call.Args[idx]
}

// clientObject resolves the variable, field or constructor function that
// provides the client expression e.
func clientObject(info *types.Info, e ast.Expr, assigns map[types.Object][]ast.Expr) types.Object {
	e = ast.Unparen(e)
	if call, ok := e.(*ast.CallExpr); ok {
		if fn := calleeFunc(info, call); fn != nil {
			return fn
		}
		return nil
	}
	obj := objOf(info, e)
	if v, ok := obj.(*types.Var); ok && !v.IsField() && v.Parent() != v.Pkg().Scope() {
		if values := assigns[obj]; len(values) == 1 {
			if call, ok := ast.Unparen(values[0]).(*ast.CallExpr); ok {
				if fn := calleeFunc(info, call); fn != nil {
					return fn
				}
			}
		}
	}
	return obj
}
