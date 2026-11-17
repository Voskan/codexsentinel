package builtin

import (
	"go/ast"
	"go/types"
	"reflect"
	"sort"
	"strings"

	"github.com/Voskan/codexsentinel/v2/analyzer"
	"github.com/Voskan/codexsentinel/v2/analyzer/result"
)

var (
	dataExposureMeta = ruleMeta{
		ID: "api-excessive-data-exposure", Title: "Sensitive Field Exposed in JSON Response", Severity: result.SeverityHigh,
		CWE: "CWE-200", OWASP: "A01:2025", Confidence: 0.85,
		Suggestion: "Tag the field with `json:\"-\"` or respond with a dedicated response type that omits it.",
		References: []string{"https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/", "https://cwe.mitre.org/data/definitions/200.html"},
	}
	massAssignmentMeta = ruleMeta{
		ID: "api-mass-assignment", Title: "Request Body Bound to Database Model", Severity: result.SeverityHigh,
		CWE: "CWE-915", OWASP: "A01:2025", Confidence: 0.8,
		Suggestion: "Decode the request into a request type with only the fields the client may change, then copy them to the model.",
		References: []string{"https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/", "https://cwe.mitre.org/data/definitions/915.html"},
	}
)

// Normalized field names that hold stored secrets and never belong in a
// response. Tokens issued to the client, such as AccessToken, are not listed.
var storedSecretNames = map[string]bool{
	"passwordhash": true, "hashedpassword": true, "passhash": true, "passwordsalt": true, "salt": true, "password": true,
	"privatekey": true, "secretkey": true, "signingkey": true, "masterkey": true, "twofactorsecret": true, "totpsecret": true,
	"recoverycodes": true, "ssn": true, "cvv": true, "cardsecuritycode": true,
}

// Normalized field names that grant privileges, money or ownership.
var privilegedNames = map[string]bool{
	"isadmin": true, "admin": true, "issuperuser": true, "role": true, "roles": true, "permissions": true,
	"balance": true, "credits": true, "price": true, "accountstatus": true, "verified": true, "emailverified": true,
}

var ormTagKeys = []string{"gorm", "db", "bun", "sql", "bson", "xorm"}

// RegisterBOPLARules reports sensitive fields serialized into HTTP responses
// and request bodies decoded straight into database models.
func RegisterBOPLARules(ctx *analyzer.AnalyzerContext) {
	registerRules(ctx, []ruleMeta{dataExposureMeta, massAssignmentMeta}, func(r *reporter) {
		for _, file := range r.pass.Files {
			for _, unit := range funcUnits(file) {
				if r.only == dataExposureMeta.ID {
					checkDataExposure(r, unit)
				} else {
					checkMassAssignment(r, unit)
				}
			}
		}
	})
}

func normalizeName(s string) string {
	return strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(s))
}

// jsonKey returns the JSON key of a field and whether encoding/json skips it.
// Only a tag of exactly "-" hides a field; "-," names it "-".
func jsonKey(f *types.Var, tag string) (string, bool) {
	value, ok := reflect.StructTag(tag).Lookup("json")
	if !ok {
		return f.Name(), false
	}
	if value == "-" {
		return "", true
	}
	name, _, _ := strings.Cut(value, ",")
	if name == "" {
		name = f.Name()
	}
	return name, false
}

// responseValues returns the expressions a call serializes into an HTTP JSON
// response.
func responseValues(info *types.Info, body ast.Node, call *ast.CallExpr) []ast.Expr {
	fn := calleeFunc(info, call)
	arg := func(i int) []ast.Expr {
		if i < len(call.Args) {
			return []ast.Expr{call.Args[i]}
		}
		return nil
	}
	switch {
	case isMethod(fn, "encoding/json", "Encoder", "Encode"):
		if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && encoderOnResponse(info, body, sel.X) {
			return arg(0)
		}
	case isMethod(fn, "github.com/gin-gonic/gin", "Context", "JSON", "IndentedJSON", "PureJSON", "SecureJSON", "AsciiJSON", "JSONP"),
		isMethod(fn, "github.com/labstack/echo", "Context", "JSON", "JSONPretty", "JSONP"):
		return arg(1)
	case isMethod(fn, "github.com/gofiber/fiber", "Ctx", "JSON"):
		return arg(0)
	case isMethod(fn, "net/http", "ResponseWriter", "Write"):
		return marshaledValues(info, body, call)
	}
	return nil
}

func isResponseWriter(info *types.Info, e ast.Expr) bool {
	return typeIs(typeOf(info, e), "net/http", "ResponseWriter")
}

// encoderOnResponse reports whether e is json.NewEncoder(w) for an
// http.ResponseWriter, directly or through a local variable.
func encoderOnResponse(info *types.Info, body ast.Node, e ast.Expr) bool {
	exprs := []ast.Expr{e}
	if obj := objOf(info, ast.Unparen(e)); obj != nil {
		exprs = append(exprs, assignments(info, body)[obj]...)
	}
	for _, x := range exprs {
		call, ok := ast.Unparen(x).(*ast.CallExpr)
		if ok && isFunc(calleeFunc(info, call), "encoding/json", "NewEncoder") && len(call.Args) == 1 && isResponseWriter(info, call.Args[0]) {
			return true
		}
	}
	return false
}

// marshaledValues returns v for w.Write(b) when b is json.Marshal(v).
func marshaledValues(info *types.Info, body ast.Node, write *ast.CallExpr) []ast.Expr {
	if len(write.Args) != 1 {
		return nil
	}
	obj := objOf(info, ast.Unparen(write.Args[0]))
	if obj == nil {
		return nil
	}
	var out []ast.Expr
	for _, v := range assignments(info, body)[obj] {
		call, ok := ast.Unparen(v).(*ast.CallExpr)
		if ok && isFunc(calleeFunc(info, call), "encoding/json", "Marshal", "MarshalIndent") && len(call.Args) > 0 {
			out = append(out, call.Args[0])
		}
	}
	return out
}

// checkDataExposure reports JSON responses whose value type contains a
// stored secret without json:"-".
func checkDataExposure(r *reporter, unit funcUnit) {
	info := r.pass.TypesInfo
	inspectShallow(unit.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, v := range responseValues(info, unit.Body, call) {
			for _, typed := range valueTypes(info, v) {
				fields := exposedSecrets(r.pass.Pkg, typed, map[types.Type]bool{})
				if len(fields) == 0 {
					continue
				}
				noun := "field"
				if len(fields) > 1 {
					noun = "fields"
				}
				r.report(dataExposureMeta, call, "Type '"+types.TypeString(typed, packageName)+"' serialized to HTTP JSON response exposes sensitive "+noun+" '"+strings.Join(fields, "', '")+"' without json:\"-\" tag.")
				return true
			}
		}
		return true
	})
}

func packageName(p *types.Package) string { return p.Name() }

// valueTypes returns the static type of v and, for a map or slice literal
// with interface elements such as gin.H{"user": u}, the types of its values.
func valueTypes(info *types.Info, v ast.Expr) []types.Type {
	v = ast.Unparen(v)
	if u, ok := v.(*ast.UnaryExpr); ok {
		v = ast.Unparen(u.X)
	}
	t := typeOf(info, v)
	if t == nil {
		return nil
	}
	out := []types.Type{t}
	lit, ok := v.(*ast.CompositeLit)
	if !ok {
		return out
	}
	var elem types.Type
	switch u := t.Underlying().(type) {
	case *types.Map:
		elem = u.Elem()
	case *types.Slice:
		elem = u.Elem()
	}
	if elem == nil || !types.IsInterface(elem) {
		return out
	}
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			elt = kv.Value
		}
		out = append(out, valueTypes(info, elt)...)
	}
	return out
}

// exposedSecrets walks t through pointers, slices, arrays, map values and
// struct fields and returns Owner.Field paths of stored secrets that JSON
// encoding would include. Types with their own MarshalJSON are trusted.
func exposedSecrets(pkg *types.Package, t types.Type, visited map[types.Type]bool) []string {
	t = types.Unalias(t)
	if visited[t] {
		return nil
	}
	visited[t] = true
	switch u := t.(type) {
	case *types.Pointer:
		return exposedSecrets(pkg, u.Elem(), visited)
	case *types.Slice:
		return exposedSecrets(pkg, u.Elem(), visited)
	case *types.Array:
		return exposedSecrets(pkg, u.Elem(), visited)
	case *types.Map:
		return exposedSecrets(pkg, u.Elem(), visited)
	case *types.Named:
		if implementsNamed(pkg, u, "encoding/json", "Marshaler", "MarshalJSON") {
			return nil
		}
		st, ok := u.Underlying().(*types.Struct)
		if !ok {
			return exposedSecrets(pkg, u.Underlying(), visited)
		}
		return structSecrets(pkg, u.Obj().Name(), st, visited)
	case *types.Struct:
		return structSecrets(pkg, "struct", u, visited)
	}
	return nil
}

func structSecrets(pkg *types.Package, owner string, st *types.Struct, visited map[types.Type]bool) []string {
	var out []string
	inputType := hasAnySuffix(owner, "Request", "Input", "Login", "Credentials")
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		key, hidden := jsonKey(f, st.Tag(i))
		if hidden || (!f.Exported() && !f.Embedded()) {
			continue
		}
		if f.Embedded() {
			if _, tagged := reflect.StructTag(st.Tag(i)).Lookup("json"); !tagged {
				out = append(out, exposedSecrets(pkg, f.Type(), visited)...)
				continue
			}
		}
		name := normalizeName(f.Name())
		if storedSecretNames[name] || storedSecretNames[normalizeName(key)] {
			if (name == "password" && inputType) || isBool(f.Type()) {
				continue
			}
			out = append(out, owner+"."+f.Name())
			continue
		}
		out = append(out, exposedSecrets(pkg, f.Type(), visited)...)
	}
	sort.Strings(out)
	return out
}

func hasAnySuffix(s string, suffixes ...string) bool {
	for _, suf := range suffixes {
		if strings.HasSuffix(s, suf) {
			return true
		}
	}
	return false
}

func isBool(t types.Type) bool {
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Kind() == types.Bool
}

// boundTarget returns the destination argument when call decodes client
// input: a JSON decoder or json.Unmarshal reading the request body, or a
// framework bind method.
func boundTarget(info *types.Info, body ast.Node, call *ast.CallExpr) ast.Expr {
	fn := calleeFunc(info, call)
	if len(call.Args) == 0 || fn == nil {
		return nil
	}
	switch {
	case isMethod(fn, "encoding/json", "Decoder", "Decode"):
		if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && decoderOnRequest(info, body, sel.X) {
			return call.Args[0]
		}
	case isFunc(fn, "encoding/json", "Unmarshal"):
		if len(call.Args) == 2 && readsRequest(info, body, call.Args[0], 3) {
			return call.Args[1]
		}
	case isMethod(fn, "github.com/gin-gonic/gin", "Context", fn.Name()) && (strings.HasPrefix(fn.Name(), "Bind") || strings.HasPrefix(fn.Name(), "ShouldBind")):
		return call.Args[0]
	case isMethod(fn, "github.com/labstack/echo", "Context", "Bind"), isMethod(fn, "github.com/gofiber/fiber", "Ctx", "BodyParser"):
		return call.Args[0]
	}
	return nil
}

func decoderOnRequest(info *types.Info, body ast.Node, e ast.Expr) bool {
	exprs := []ast.Expr{e}
	if obj := objOf(info, ast.Unparen(e)); obj != nil {
		exprs = append(exprs, assignments(info, body)[obj]...)
	}
	for _, x := range exprs {
		call, ok := ast.Unparen(x).(*ast.CallExpr)
		if ok && isFunc(calleeFunc(info, call), "encoding/json", "NewDecoder") && len(call.Args) == 1 && readsRequest(info, body, call.Args[0], 3) {
			return true
		}
	}
	return false
}

// readsRequest reports whether e reads the body of an *http.Request, directly
// or through local variables up to depth assignments away.
func readsRequest(info *types.Info, body ast.Node, e ast.Expr, depth int) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if found {
			return false
		}
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if x.Sel.Name == "Body" && typeIs(typeOf(info, x.X), "net/http", "Request") {
				found = true
			}
		case *ast.Ident:
			if depth > 0 {
				if obj := info.Uses[x]; obj != nil {
					for _, v := range assignments(info, body)[obj] {
						if readsRequest(info, body, v, depth-1) {
							found = true
						}
					}
				}
			}
		}
		return true
	})
	return found
}

// checkMassAssignment reports client input decoded into a database model
// with privileged fields the client can then set.
func checkMassAssignment(r *reporter, unit funcUnit) {
	info := r.pass.TypesInfo
	inspectShallow(unit.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		dst := boundTarget(info, unit.Body, call)
		if dst == nil {
			return true
		}
		named, st := modelStruct(typeOf(info, dst))
		if st == nil {
			return true
		}
		if !hasORMTags(st, map[*types.Struct]bool{}) && !persisted(info, unit.Body, dst) {
			return true
		}
		fields := bindablePrivileged(st, map[*types.Struct]bool{})
		if len(fields) == 0 {
			return true
		}
		r.report(massAssignmentMeta, call, "Client input is decoded directly into database model '"+named.Obj().Name()+"' whose fields '"+strings.Join(fields, "', '")+"' the client can then set.")
		return true
	})
}

func modelStruct(t types.Type) (*types.Named, *types.Struct) {
	for t != nil {
		p, ok := types.Unalias(t).(*types.Pointer)
		if !ok {
			break
		}
		t = p.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok {
		return nil, nil
	}
	st, _ := named.Underlying().(*types.Struct)
	return named, st
}

func hasORMTags(st *types.Struct, seen map[*types.Struct]bool) bool {
	if seen[st] {
		return false
	}
	seen[st] = true
	for i := 0; i < st.NumFields(); i++ {
		tag := reflect.StructTag(st.Tag(i))
		for _, key := range ormTagKeys {
			if _, ok := tag.Lookup(key); ok {
				return true
			}
		}
		if st.Field(i).Embedded() {
			if _, inner := modelStruct(st.Field(i).Type()); inner != nil && hasORMTags(inner, seen) {
				return true
			}
		}
	}
	return false
}

// persisted reports whether dst (or the variable it points to) is passed to
// a Save, Create, Update, Updates or Insert call in the function.
func persisted(info *types.Info, body ast.Node, dst ast.Expr) bool {
	target := dst
	if u, ok := ast.Unparen(dst).(*ast.UnaryExpr); ok {
		target = u.X
	}
	obj := objOf(info, ast.Unparen(target))
	if obj == nil {
		return false
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if found || !ok {
			return !found
		}
		sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !ok || !nameIn(sel.Sel.Name, []string{"Save", "Create", "Update", "Updates", "Insert"}) {
			return true
		}
		for _, arg := range call.Args {
			a := ast.Unparen(arg)
			if u, ok := a.(*ast.UnaryExpr); ok {
				a = ast.Unparen(u.X)
			}
			if objOf(info, a) == obj {
				found = true
			}
		}
		return true
	})
	return found
}

// bindablePrivileged returns privileged fields that JSON decoding can set:
// exported, not tagged json:"-" and not read-only for gorm.
func bindablePrivileged(st *types.Struct, seen map[*types.Struct]bool) []string {
	if seen[st] {
		return nil
	}
	seen[st] = true
	var out []string
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		key, hidden := jsonKey(f, st.Tag(i))
		if hidden {
			continue
		}
		if f.Embedded() {
			if _, inner := modelStruct(f.Type()); inner != nil {
				out = append(out, bindablePrivileged(inner, seen)...)
			}
			continue
		}
		if !f.Exported() || readOnlyGorm(st.Tag(i)) {
			continue
		}
		if privilegedNames[normalizeName(f.Name())] || privilegedNames[normalizeName(key)] {
			out = append(out, f.Name())
		}
	}
	return out
}

func readOnlyGorm(tag string) bool {
	g, ok := reflect.StructTag(tag).Lookup("gorm")
	if !ok {
		return false
	}
	for _, part := range strings.Split(g, ";") {
		part = strings.TrimSpace(part)
		if part == "-" || part == "->" || strings.HasPrefix(part, "<-:false") || strings.HasPrefix(part, "-:") {
			return true
		}
	}
	return false
}
