package builtin

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/Voskan/codexsentinel/v2/analyzer"
	"github.com/Voskan/codexsentinel/v2/analyzer/result"
	"golang.org/x/tools/go/types/typeutil"
)

var (
	unsafeMemoryMeta = ruleMeta{
		ID: "unsafe-memory-manipulation", Title: "Unsafe Memory Manipulation", Severity: result.SeverityHigh,
		CWE: "CWE-119", OWASP: "A06:2025", Confidence: 0.8,
		Suggestion: "Use unsafe.Slice, unsafe.String, unsafe.SliceData and unsafe.Add in a single expression, and bound lengths taken from input.",
		References: []string{"https://pkg.go.dev/unsafe#Pointer", "https://cwe.mitre.org/data/definitions/119.html"},
	}
	errIgnoredMeta = ruleMeta{
		ID: "security-err-ignored", Title: "Security-Critical Error Ignored", Severity: result.SeverityHigh,
		CWE: "CWE-252", OWASP: "A10:2025", Confidence: 0.9,
		Suggestion: "Check the error and stop when the operation fails.",
		References: []string{"https://cwe.mitre.org/data/definitions/252.html"},
	}
)

// RegisterUnsafeErrcheckRules reports dangerous unsafe patterns and ignored
// errors of calls whose failure leaves the program insecure.
func RegisterUnsafeErrcheckRules(ctx *analyzer.AnalyzerContext) {
	registerRules(ctx, []ruleMeta{unsafeMemoryMeta, errIgnoredMeta}, func(r *reporter) {
		for _, file := range r.pass.Files {
			if r.only == unsafeMemoryMeta.ID {
				checkUnsafeMemory(r, file)
				continue
			}
			checkIgnoredErrors(r, file)
			for _, unit := range funcUnits(file) {
				checkRowsErr(r, unit)
			}
		}
	})
}

// checkUnsafeMemory reports reflect.SliceHeader and reflect.StringHeader, a
// pointer kept as a uintptr in a variable and converted back, and
// unsafe.Slice or unsafe.String with an unchecked length.
func checkUnsafeMemory(r *reporter, file *ast.File) {
	info := r.pass.TypesInfo
	ast.Inspect(file, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if tn, ok := info.Uses[sel.Sel].(*types.TypeName); ok && tn.Pkg() != nil && tn.Pkg().Path() == "reflect" &&
				(tn.Name() == "SliceHeader" || tn.Name() == "StringHeader") {
				r.report(unsafeMemoryMeta, sel, "reflect."+tn.Name()+" is deprecated and its Data field is not seen by the garbage collector; use unsafe.Slice, unsafe.String or unsafe.SliceData.")
			}
		}
		return true
	})
	for _, unit := range funcUnits(file) {
		checkStoredUintptr(r, unit)
		checkUnsafeLength(r, unit)
	}
}

func isConversion(info *types.Info, call *ast.CallExpr, kind types.BasicKind) bool {
	tv, ok := info.Types[call.Fun]
	if !ok || !tv.IsType() || len(call.Args) != 1 {
		return false
	}
	b, ok := tv.Type.(*types.Basic)
	return ok && b.Kind() == kind
}

// isPointerToUintptr reports whether e is uintptr(unsafe.Pointer(x)).
func isPointerToUintptr(info *types.Info, e ast.Expr) bool {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok || !isConversion(info, call, types.Uintptr) {
		return false
	}
	inner, ok := ast.Unparen(call.Args[0]).(*ast.CallExpr)
	return ok && isConversion(info, inner, types.UnsafePointer)
}

// checkStoredUintptr reports a variable holding uintptr(unsafe.Pointer(p))
// that is later converted back to unsafe.Pointer. The garbage collector does
// not treat the integer as a reference, so the object can move or be freed in
// between. A uintptr kept only for printing or alignment checks is fine.
func checkStoredUintptr(r *reporter, unit funcUnit) {
	info := r.pass.TypesInfo
	stored := map[types.Object]ast.Node{}
	inspectShallow(unit.Body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			if len(s.Lhs) == len(s.Rhs) {
				for i, rhs := range s.Rhs {
					if obj := objOf(info, s.Lhs[i]); obj != nil && isPointerToUintptr(info, rhs) {
						stored[obj] = s
					}
				}
			}
		case *ast.ValueSpec:
			if len(s.Names) == len(s.Values) {
				for i, v := range s.Values {
					if obj := info.Defs[s.Names[i]]; obj != nil && isPointerToUintptr(info, v) {
						stored[obj] = s
					}
				}
			}
		}
		return true
	})
	if len(stored) == 0 {
		return
	}
	reported := map[types.Object]bool{}
	inspectShallow(unit.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isConversion(info, call, types.UnsafePointer) {
			return true
		}
		ast.Inspect(call.Args[0], func(m ast.Node) bool {
			id, ok := m.(*ast.Ident)
			if !ok {
				return true
			}
			obj := info.Uses[id]
			if def, ok := stored[obj]; ok && !reported[obj] && def.Pos() < call.Pos() {
				reported[obj] = true
				r.report(unsafeMemoryMeta, def, "A pointer is stored as uintptr in "+id.Name+" and converted back to unsafe.Pointer later; the garbage collector may move or free the object in between. Do the arithmetic in one expression with unsafe.Add.")
			}
			return true
		})
		return true
	})
}

func unsafeBuiltin(info *types.Info, call *ast.CallExpr) string {
	b, ok := typeutil.Callee(info, call).(*types.Builtin)
	if !ok {
		return ""
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	if id, ok := sel.X.(*ast.Ident); ok {
		if pn, ok := info.Uses[id].(*types.PkgName); ok && pn.Imported().Path() == "unsafe" {
			return b.Name()
		}
	}
	return ""
}

// checkUnsafeLength reports unsafe.Slice and unsafe.String whose length is
// neither constant, nor derived from len or cap, nor compared before the call.
func checkUnsafeLength(r *reporter, unit funcUnit) {
	info := r.pass.TypesInfo
	inspectShallow(unit.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		name := unsafeBuiltin(info, call)
		if name != "Slice" && name != "String" {
			return true
		}
		length := ast.Unparen(call.Args[1])
		if _, ok := constInt(info, length); ok || usesLenOrCap(info, length) {
			return true
		}
		obj := objOf(info, length)
		if obj == nil {
			if conv, ok := length.(*ast.CallExpr); ok && len(conv.Args) == 1 && info.Types[conv.Fun].IsType() {
				obj = objOf(info, ast.Unparen(conv.Args[0]))
			}
		}
		if obj == nil || comparedBefore(info, unit.Body, obj, call.Pos()) || derivedFromLen(info, unit.Body, obj) {
			return true
		}
		r.report(unsafeMemoryMeta, call, "unsafe."+name+" uses a length that is not checked against the size of the underlying memory; a larger value reads or writes out of bounds.")
		return true
	})
}

func usesLenOrCap(info *types.Info, e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if b, ok := typeutil.Callee(info, call).(*types.Builtin); ok && (b.Name() == "len" || b.Name() == "cap") {
				found = true
			}
		}
		return !found
	})
	return found
}

func derivedFromLen(info *types.Info, body ast.Node, obj types.Object) bool {
	for _, v := range assignments(info, body)[obj] {
		if usesLenOrCap(info, v) {
			return true
		}
	}
	return false
}

// comparedBefore reports whether obj appears in an ordering comparison
// before pos.
func comparedBefore(info *types.Info, body ast.Node, obj types.Object, pos token.Pos) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		b, ok := n.(*ast.BinaryExpr)
		if found || !ok || b.Pos() >= pos {
			return !found
		}
		switch b.Op {
		case token.LSS, token.LEQ, token.GTR, token.GEQ:
			for _, side := range []ast.Expr{b.X, b.Y} {
				ast.Inspect(side, func(m ast.Node) bool {
					if id, ok := m.(*ast.Ident); ok && info.Uses[id] == obj {
						found = true
					}
					return !found
				})
			}
		}
		return !found
	})
	return found
}

// criticalErr returns the severity and consequence when ignoring the error of
// call is a security problem.
func criticalErr(info *types.Info, call *ast.CallExpr) (result.Severity, string) {
	fn := calleeFunc(info, call)
	switch {
	case isFunc(fn, "crypto/rand", "Read"), isRandReaderRead(info, call, fn):
		return result.SeverityCritical, "If reading random bytes fails, the buffer keeps its zero value and is used as a key, nonce or token."
	case isFunc(fn, "golang.org/x/crypto/bcrypt", "CompareHashAndPassword"):
		return result.SeverityCritical, "The result of the password comparison is ignored, so any password is accepted."
	case isMethod(fn, "crypto/tls", "Conn", "Handshake", "HandshakeContext"):
		return result.SeverityHigh, "A failed TLS handshake is ignored and the connection is used without an authenticated peer."
	case isMethod(fn, "crypto/x509", "Certificate", "Verify"):
		return result.SeverityHigh, "A failed certificate verification is ignored and the certificate is trusted anyway."
	case isFunc(fn, "os", "Chmod", "Chown", "Lchown"):
		return result.SeverityHigh, "If changing file permissions or ownership fails, the file keeps its previous, possibly wider, access."
	case isFunc(fn, "syscall", "Setuid", "Setgid", "Chroot"):
		return result.SeverityHigh, "If dropping privileges or entering the chroot fails, the process keeps running with full privileges."
	case isMethod(fn, "database/sql", "Rows", "Err"):
		return result.SeverityMedium, "An error that ended the row iteration is ignored, so a partial result is treated as complete."
	}
	return "", ""
}

// isRandReaderRead matches rand.Reader.Read(buf) and io.ReadFull(rand.Reader, buf).
func isRandReaderRead(info *types.Info, call *ast.CallExpr, fn *types.Func) bool {
	isRandReader := func(e ast.Expr) bool {
		v, ok := objOf(info, ast.Unparen(e)).(*types.Var)
		return ok && v.Pkg() != nil && v.Pkg().Path() == "crypto/rand" && v.Name() == "Reader"
	}
	if isFunc(fn, "io", "ReadFull", "ReadAtLeast") && len(call.Args) > 0 {
		return isRandReader(call.Args[0])
	}
	if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "Read" {
		return isRandReader(sel.X)
	}
	return false
}

// checkIgnoredErrors reports calls from the critical list whose error result
// is dropped, either by using the call as a statement or by assigning the
// error to the blank identifier.
func checkIgnoredErrors(r *reporter, file *ast.File) {
	info := r.pass.TypesInfo
	ast.Inspect(file, func(n ast.Node) bool {
		var call *ast.CallExpr
		switch s := n.(type) {
		case *ast.ExprStmt:
			call, _ = ast.Unparen(s.X).(*ast.CallExpr)
		case *ast.AssignStmt:
			if len(s.Rhs) == 1 {
				if c, ok := ast.Unparen(s.Rhs[0]).(*ast.CallExpr); ok && blankError(info, c, s.Lhs) {
					call = c
				}
			}
		}
		if call == nil {
			return true
		}
		if severity, why := criticalErr(info, call); severity != "" {
			r.reportWith(errIgnoredMeta, call, "The error of "+calleeName(info, call)+" is ignored. "+why, severity, nil)
		}
		return true
	})
}

func calleeName(info *types.Info, call *ast.CallExpr) string {
	if fn := calleeFunc(info, call); fn != nil {
		if recv := recvOf(fn); recv != nil {
			_, name := namedOf(recv.Type())
			return name + "." + fn.Name()
		}
		if fn.Pkg() != nil {
			return fn.Pkg().Name() + "." + fn.Name()
		}
		return fn.Name()
	}
	return "the call"
}

// blankError reports whether the error result of call is assigned to _.
func blankError(info *types.Info, call *ast.CallExpr, lhs []ast.Expr) bool {
	tv, ok := info.Types[call]
	if !ok {
		return false
	}
	var results []types.Type
	if tuple, ok := tv.Type.(*types.Tuple); ok {
		for i := 0; i < tuple.Len(); i++ {
			results = append(results, tuple.At(i).Type())
		}
	} else {
		results = []types.Type{tv.Type}
	}
	if len(results) != len(lhs) {
		return false
	}
	errType := types.Universe.Lookup("error").Type()
	for i, t := range results {
		if id, ok := lhs[i].(*ast.Ident); ok && id.Name == "_" && types.Identical(t, errType) {
			return true
		}
	}
	return false
}

// checkRowsErr reports rows iterated with Next whose Err is never consulted.
// Rows handed to other code are not reported.
func checkRowsErr(r *reporter, unit funcUnit) {
	info := r.pass.TypesInfo
	for _, rc := range resourceAssignments(info, unit.Body, isRowsQuery) {
		if rc.discard || !iteratesRows(info, unit.Body, rc.resource) || callsMethod(info, unit.Body, rc.resource, "Err") || escapes(info, unit.Body, rc.resource) {
			continue
		}
		r.reportWith(errIgnoredMeta, rc.call, "Rows are iterated without checking rows.Err() afterwards; an error that stops the iteration early goes unnoticed and a partial result is used.", result.SeverityMedium, nil)
	}
}

func iteratesRows(info *types.Info, body ast.Node, rows types.Object) bool {
	found := false
	inspectShallow(body, func(n ast.Node) bool {
		if loop, ok := n.(*ast.ForStmt); ok && loop.Cond != nil {
			if call, ok := ast.Unparen(loop.Cond).(*ast.CallExpr); ok {
				if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "Next" && objOf(info, ast.Unparen(sel.X)) == rows {
					found = true
				}
			}
		}
		return !found
	})
	return found
}
