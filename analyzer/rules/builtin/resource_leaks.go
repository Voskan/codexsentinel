package builtin

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
)

var (
	txRollbackMeta = ruleMeta{
		ID: "sql-tx-missing-rollback", Title: "Transaction Not Rolled Back on Early Return", Severity: result.SeverityHigh,
		CWE: "CWE-404", OWASP: "A06:2025", Confidence: 0.8, Category: "reliability",
		Suggestion: "Add `defer tx.Rollback()` right after checking the error of Begin; Rollback after Commit is a no-op.",
		References: []string{"https://cwe.mitre.org/data/definitions/404.html", "https://go.dev/doc/database/execute-transactions"},
	}
	bodyUnclosedMeta = ruleMeta{
		ID: "http-body-unclosed", Title: "HTTP Response Body Not Closed", Severity: result.SeverityHigh,
		CWE: "CWE-404", OWASP: "A06:2025", Confidence: 0.8, Category: "reliability",
		Suggestion: "Add `defer resp.Body.Close()` after checking the error; an unclosed body keeps the connection out of the pool.",
		References: []string{"https://pkg.go.dev/net/http#Client.Do"},
	}
	rowsUnclosedMeta = ruleMeta{
		ID: "sql-rows-unclosed", Title: "Query Rows Not Closed", Severity: result.SeverityHigh,
		CWE: "CWE-404", OWASP: "A06:2025", Confidence: 0.8, Category: "reliability",
		Suggestion: "Add `defer rows.Close()` after checking the error, and check rows.Err() after the loop.",
		References: []string{"https://go.dev/doc/database/querying#multiple_rows"},
	}
	deferLoopMeta = ruleMeta{
		ID: "defer-in-loop", Title: "Defer Inside a Loop", Severity: result.SeverityMedium,
		CWE: "CWE-400", OWASP: "A06:2025", Confidence: 0.9, Category: "reliability",
		Suggestion: "Move the loop body into a function so that the deferred call runs at the end of each iteration, or release the resource explicitly.",
		References: []string{"https://go.dev/ref/spec#Defer_statements"},
	}
	goroutineLeakMeta = ruleMeta{
		ID: "goroutine-channel-leak", Title: "Goroutine Blocked on Unbuffered Channel", Severity: result.SeverityMedium,
		CWE: "CWE-400", OWASP: "A06:2025", Confidence: 0.8, Category: "reliability",
		Suggestion: "Give the channel a buffer of 1 (make(chan T, 1)) or send inside a select that also waits on ctx.Done().",
		References: []string{"https://go.dev/blog/pipelines"},
	}
)

// RegisterResourceLeakRules reports transactions, response bodies and query
// rows that are not released, defers inside loops and goroutines that can
// block forever on an unbuffered channel.
func RegisterResourceLeakRules(ctx *analyzer.AnalyzerContext) {
	metas := []ruleMeta{txRollbackMeta, bodyUnclosedMeta, rowsUnclosedMeta, deferLoopMeta, goroutineLeakMeta}
	registerRules(ctx, metas, func(r *reporter) {
		for _, file := range r.pass.Files {
			for _, unit := range funcUnits(file) {
				switch r.only {
				case txRollbackMeta.ID:
					checkTxRollback(r, unit)
				case bodyUnclosedMeta.ID:
					checkUnclosed(r, unit, bodyUnclosedMeta)
				case rowsUnclosedMeta.ID:
					checkUnclosed(r, unit, rowsUnclosedMeta)
				case goroutineLeakMeta.ID:
					checkGoroutineLeak(r, unit)
				}
			}
			if r.only == deferLoopMeta.ID {
				for _, decl := range file.Decls {
					if fd, ok := decl.(*ast.FuncDecl); ok {
						checkDeferInLoop(r, fd.Body, false)
					}
				}
			}
		}
	})
}

// resourceCall describes a call that returns a resource and its error.
type resourceCall struct {
	call     *ast.CallExpr
	resource types.Object // nil when the resource is discarded with _
	err      types.Object
	discard  bool
}

// resourceAssignments finds `x, err := <call>` statements whose call matches
// match, in the function body without nested literals.
func resourceAssignments(info *types.Info, body ast.Node, match func(*types.Func) bool) []resourceCall {
	var out []resourceCall
	inspectShallow(body, func(n ast.Node) bool {
		var lhs, rhs []ast.Expr
		switch s := n.(type) {
		case *ast.AssignStmt:
			lhs, rhs = s.Lhs, s.Rhs
		case *ast.ValueSpec:
			for _, name := range s.Names {
				lhs = append(lhs, name)
			}
			rhs = s.Values
		default:
			return true
		}
		if len(rhs) != 1 || len(lhs) == 0 {
			return true
		}
		call, ok := ast.Unparen(rhs[0]).(*ast.CallExpr)
		if !ok || !match(calleeFunc(info, call)) {
			return true
		}
		rc := resourceCall{call: call}
		if id, ok := lhs[0].(*ast.Ident); ok && id.Name == "_" {
			rc.discard = true
		} else {
			rc.resource = objOf(info, lhs[0])
		}
		if len(lhs) > 1 {
			rc.err = objOf(info, lhs[1])
		}
		if rc.resource != nil || rc.discard {
			out = append(out, rc)
		}
		return true
	})
	return out
}

func isTxBegin(fn *types.Func) bool {
	return isMethod(fn, "database/sql", "DB", "Begin", "BeginTx") || isMethod(fn, "database/sql", "Conn", "BeginTx") ||
		isMethod(fn, "github.com/jmoiron/sqlx", "DB", "Beginx", "BeginTxx") ||
		isMethod(fn, "github.com/jackc/pgx", "Conn", "Begin", "BeginTx") ||
		isMethod(fn, "github.com/jackc/pgx/v5/pgxpool", "Pool", "Begin", "BeginTx") ||
		isMethod(fn, "github.com/jackc/pgx/v4/pgxpool", "Pool", "Begin", "BeginTx")
}

// checkTxRollback reports a transaction that some return path leaves open:
// there is no deferred Rollback and a return after Begin neither commits nor
// rolls back. Transactions handed to other code are not reported.
func checkTxRollback(r *reporter, unit funcUnit) {
	info := r.pass.TypesInfo
	for _, rc := range resourceAssignments(info, unit.Body, isTxBegin) {
		if rc.discard || deferredMethod(info, unit.Body, rc.resource, "Rollback") || escapes(info, unit.Body, rc.resource) {
			continue
		}
		if leak := unreleasedReturn(info, unit.Body, rc, "Rollback", "Commit"); leak != nil {
			r.report(txRollbackMeta, rc.call, "Transaction is not rolled back when the function returns early; the connection and its locks stay held until the transaction times out.")
		}
	}
}

// unreleasedReturn returns a return statement after the resource call that
// can leave the resource open. A return is safe when it calls a release method
// itself, is inside the error check of the call, or follows a release call
// whose block also contains the return.
func unreleasedReturn(info *types.Info, body ast.Node, rc resourceCall, release ...string) *ast.ReturnStmt {
	type scoped struct {
		pos   token.Pos
		scope ast.Node
	}
	var releases []scoped
	var scopes []ast.Node
	var returns []*ast.ReturnStmt
	var errCheck *ast.IfStmt
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.BlockStmt, *ast.CaseClause, *ast.CommClause:
			scopes = append(scopes, x)
		case *ast.IfStmt:
			if errCheck == nil && rc.err != nil && x.Cond.Pos() >= rc.call.End() && testsErr(info, x.Cond, rc.err) {
				errCheck = x
			}
		case *ast.CallExpr:
			if releasedObj(info, x, release) == rc.resource {
				releases = append(releases, scoped{x.Pos(), innermost(scopes, x)})
			}
		case *ast.ReturnStmt:
			if x.Pos() > rc.call.End() {
				returns = append(returns, x)
			}
		}
		return true
	})
	for _, ret := range returns {
		if callsMethod(info, ret, rc.resource, release...) || errCheck != nil && within(errCheck.Body, ret) {
			continue
		}
		safe := false
		for _, rel := range releases {
			if rel.pos < ret.Pos() && rel.scope != nil && within(rel.scope, ret) {
				safe = true
				break
			}
		}
		if !safe {
			return ret
		}
	}
	return nil
}

func within(outer, inner ast.Node) bool {
	return outer.Pos() <= inner.Pos() && inner.End() <= outer.End()
}

// innermost returns the smallest scope among scopes that contains n.
func innermost(scopes []ast.Node, n ast.Node) ast.Node {
	var best ast.Node
	for _, sc := range scopes {
		if within(sc, n) && (best == nil || sc.Pos() >= best.Pos()) {
			best = sc
		}
	}
	return best
}

// testsErr reports whether cond is `err != nil` for errObj.
func testsErr(info *types.Info, cond ast.Expr, errObj types.Object) bool {
	b, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	return ok && b.Op == token.NEQ && objOf(info, ast.Unparen(b.X)) == errObj
}

// releasedObj returns the variable whose method among methods call invokes,
// looking through a Body field: both rows.Close() and resp.Body.Close()
// return the variable.
func releasedObj(info *types.Info, call *ast.CallExpr, methods []string) types.Object {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || !nameIn(sel.Sel.Name, methods) {
		return nil
	}
	x := ast.Unparen(sel.X)
	if inner, ok := x.(*ast.SelectorExpr); ok && inner.Sel.Name == "Body" {
		x = ast.Unparen(inner.X)
	}
	return objOf(info, x)
}

// callsMethod reports whether node contains a call releasing obj with one of
// methods.
func callsMethod(info *types.Info, node ast.Node, obj types.Object, methods ...string) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && releasedObj(info, call, methods) == obj {
			found = true
		}
		return !found
	})
	return found
}

// deferredMethod reports whether body defers obj.<method>(), directly or in a
// deferred function literal.
func deferredMethod(info *types.Info, body ast.Node, obj types.Object, method string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if d, ok := n.(*ast.DeferStmt); ok && callsMethod(info, d.Call, obj, method) {
			found = true
		}
		return !found
	})
	return found
}

// escapes reports whether obj leaves the function's control: it is returned,
// assigned, stored in a composite literal, sent on a channel, used inside a
// function literal other than to release it, or passed to a call. Passing only
// the Body field of a response to a standard library function, such as
// io.ReadAll, does not hand over the responsibility to close it.
func escapes(info *types.Info, body ast.Node, obj types.Object) bool {
	refersTo := func(e ast.Expr) (match, viaBody bool) {
		e = ast.Unparen(e)
		if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.AND {
			e = ast.Unparen(u.X)
		}
		if sel, ok := e.(*ast.SelectorExpr); ok && sel.Sel.Name == "Body" {
			e, viaBody = ast.Unparen(sel.X), true
		}
		return objOf(info, e) == obj, viaBody
	}
	esc := false
	mark := func(exprs ...ast.Expr) {
		for _, e := range exprs {
			if m, _ := refersTo(e); m {
				esc = true
			}
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		if esc {
			return false
		}
		switch x := n.(type) {
		case *ast.FuncLit:
			esc = usedOtherThanClose(info, x.Body, obj)
			return false
		case *ast.ReturnStmt:
			mark(x.Results...)
		case *ast.AssignStmt:
			mark(x.Rhs...)
		case *ast.ValueSpec:
			mark(x.Values...)
		case *ast.CompositeLit:
			for _, elt := range x.Elts {
				if kv, ok := elt.(*ast.KeyValueExpr); ok {
					elt = kv.Value
				}
				mark(elt)
			}
		case *ast.SendStmt:
			mark(x.Value)
		case *ast.CallExpr:
			for _, arg := range x.Args {
				m, viaBody := refersTo(arg)
				if m && (!viaBody || !isStdlib(calleeFunc(info, x))) {
					esc = true
				}
			}
		}
		return true
	})
	return esc
}

// usedOtherThanClose reports whether body refers to obj other than in a
// Close, Rollback or Commit call.
func usedOtherThanClose(info *types.Info, body ast.Node, obj types.Object) bool {
	used := false
	ast.Inspect(body, func(n ast.Node) bool {
		if used {
			return false
		}
		if call, ok := n.(*ast.CallExpr); ok && len(call.Args) == 0 && releasedObj(info, call, []string{"Close", "Rollback", "Commit"}) == obj {
			return false
		}
		if id, ok := n.(*ast.Ident); ok && info.Uses[id] == obj {
			used = true
		}
		return true
	})
	return used
}

func isStdlib(fn *types.Func) bool {
	if fn == nil || fn.Pkg() == nil {
		return false
	}
	path := fn.Pkg().Path()
	first, _, _ := strings.Cut(path, "/")
	return !strings.Contains(first, ".")
}

func isHTTPResponseCall(fn *types.Func) bool {
	return isFunc(fn, "net/http", "Get", "Head", "Post", "PostForm") ||
		isMethod(fn, "net/http", "Client", "Do", "Get", "Head", "Post", "PostForm")
}

func isRowsQuery(fn *types.Func) bool {
	if fn == nil {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Results().Len() == 0 {
		return false
	}
	res := sig.Results().At(0).Type()
	return (isMethod(fn, "database/sql", "DB", "Query", "QueryContext") || isMethod(fn, "database/sql", "Tx", "Query", "QueryContext") ||
		isMethod(fn, "database/sql", "Conn", "QueryContext") || isMethod(fn, "database/sql", "Stmt", "Query", "QueryContext") ||
		isMethod(fn, "github.com/jmoiron/sqlx", "DB", "Queryx", "QueryxContext") ||
		isMethod(fn, "github.com/jackc/pgx", "Conn", "Query") ||
		isMethod(fn, "github.com/jackc/pgx/v5/pgxpool", "Pool", "Query") || isMethod(fn, "github.com/jackc/pgx/v4/pgxpool", "Pool", "Query")) &&
		(typeIs(res, "database/sql", "Rows") || typeIs(res, "github.com/jmoiron/sqlx", "Rows") || typeIs(res, "github.com/jackc/pgx", "Rows"))
}

// checkUnclosed reports response bodies and query rows that the function
// neither closes nor hands to other code.
func checkUnclosed(r *reporter, unit funcUnit, meta ruleMeta) {
	info := r.pass.TypesInfo
	match, what := isHTTPResponseCall, "Response body"
	if meta.ID == rowsUnclosedMeta.ID {
		match, what = isRowsQuery, "Query rows"
	}
	for _, rc := range resourceAssignments(info, unit.Body, match) {
		if rc.discard {
			r.report(meta, rc.call, what+" is discarded without being closed; the connection is never released.")
			continue
		}
		if callsMethod(info, unit.Body, rc.resource, "Close") || escapes(info, unit.Body, rc.resource) {
			continue
		}
		r.report(meta, rc.call, what+" is never closed; the connection is not returned to the pool.")
	}
}

// checkDeferInLoop reports defer statements whose loop body is in the same
// function. Function literals are separate units with their own scope.
func checkDeferInLoop(r *reporter, node ast.Node, inLoop bool) {
	if node == nil {
		return
	}
	ast.Inspect(node, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			checkDeferInLoop(r, x.Body, false)
			return false
		case *ast.ForStmt:
			if x != node {
				checkDeferInLoop(r, x.Body, true)
				return false
			}
		case *ast.RangeStmt:
			if x != node {
				checkDeferInLoop(r, x.Body, true)
				return false
			}
		case *ast.DeferStmt:
			if inLoop {
				r.report(deferLoopMeta, x, "defer inside a loop runs only when the function returns; resources acquired in every iteration stay open until then.")
			}
		}
		return true
	})
}

// checkGoroutineLeak reports a goroutine that sends on an unbuffered channel
// outside a select while its parent can stop waiting for the value: it
// selects on another channel too, or returns before receiving.
func checkGoroutineLeak(r *reporter, unit funcUnit) {
	info := r.pass.TypesInfo
	if !hasCancellationParam(info, unit.Type) {
		return
	}
	chans := unbufferedChans(info, unit.Body)
	if len(chans) == 0 {
		return
	}
	inspectShallow(unit.Body, func(n ast.Node) bool {
		gs, ok := n.(*ast.GoStmt)
		if !ok {
			return true
		}
		lit, ok := ast.Unparen(gs.Call.Fun).(*ast.FuncLit)
		if !ok {
			return true
		}
		for _, send := range bareSends(info, lit.Body, chans) {
			if parentAbandons(info, unit.Body, gs, objOf(info, send.Chan)) {
				r.report(goroutineLeakMeta, send, "Goroutine sends on an unbuffered channel that the caller may stop reading (cancellation or early return); the goroutine then blocks forever.")
			}
		}
		return true
	})
}

func hasCancellationParam(info *types.Info, ft *ast.FuncType) bool {
	for _, p := range params(info, ft) {
		if typeIs(p.Type(), "context", "Context") || typeIs(p.Type(), "net/http", "Request") {
			return true
		}
	}
	return false
}

// unbufferedChans returns the channels created with make(chan T) or
// make(chan T, 0) in body.
func unbufferedChans(info *types.Info, body ast.Node) map[types.Object]bool {
	out := map[types.Object]bool{}
	for obj, values := range assignments(info, body) {
		if len(values) != 1 {
			continue
		}
		call, ok := ast.Unparen(values[0]).(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			continue
		}
		if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "make" {
			continue
		}
		if t := typeOf(info, call.Args[0]); t == nil {
			continue
		} else if _, ok := t.Underlying().(*types.Chan); !ok {
			continue
		}
		if len(call.Args) == 1 {
			out[obj] = true
		} else if size, ok := constInt(info, call.Args[1]); ok && size == 0 {
			out[obj] = true
		}
	}
	return out
}

// bareSends returns sends on chans in body that are not select cases.
func bareSends(info *types.Info, body ast.Node, chans map[types.Object]bool) []*ast.SendStmt {
	var out []*ast.SendStmt
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CommClause:
			for _, stmt := range x.Body {
				out = append(out, bareSends(info, stmt, chans)...)
			}
			return false
		case *ast.SendStmt:
			if chans[objOf(info, x.Chan)] {
				out = append(out, x)
			}
		}
		return true
	})
	return out
}

// parentAbandons reports whether the function can stop waiting for ch after
// starting the goroutine: a select receives from ch next to other cases, or a
// return lies between the go statement and the first receive from ch.
func parentAbandons(info *types.Info, body ast.Node, gs *ast.GoStmt, ch types.Object) bool {
	firstRecv := token.NoPos
	abandons := false
	isRecv := func(e ast.Expr) bool {
		u, ok := ast.Unparen(e).(*ast.UnaryExpr)
		return ok && u.Op == token.ARROW && objOf(info, u.X) == ch
	}
	inspectShallow(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectStmt:
			receives, others := false, 0
			for _, c := range x.Body.List {
				cc := c.(*ast.CommClause)
				if commReceives(cc.Comm, isRecv) {
					receives = true
				} else {
					others++
				}
			}
			if receives && others > 0 {
				abandons = true
			}
		case *ast.UnaryExpr:
			if isRecv(x) && x.Pos() > gs.End() && (firstRecv == token.NoPos || x.Pos() < firstRecv) {
				firstRecv = x.Pos()
			}
		case *ast.RangeStmt:
			if objOf(info, x.X) == ch && x.Pos() > gs.End() && (firstRecv == token.NoPos || x.Pos() < firstRecv) {
				firstRecv = x.Pos()
			}
		}
		return true
	})
	if abandons || firstRecv == token.NoPos {
		return abandons
	}
	inspectShallow(body, func(n ast.Node) bool {
		if ret, ok := n.(*ast.ReturnStmt); ok && ret.Pos() > gs.End() && ret.End() <= firstRecv {
			abandons = true
		}
		return !abandons
	})
	return abandons
}

func commReceives(comm ast.Stmt, isRecv func(ast.Expr) bool) bool {
	switch s := comm.(type) {
	case *ast.ExprStmt:
		return isRecv(s.X)
	case *ast.AssignStmt:
		return len(s.Rhs) == 1 && isRecv(s.Rhs[0])
	}
	return false
}
