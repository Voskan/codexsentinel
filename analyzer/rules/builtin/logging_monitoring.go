package builtin

import (
	"fmt"
	"go/ast"
	"go/types"
	"reflect"
	"regexp"
	"strings"

	"github.com/Voskan/codexsentinel/v2/analyzer"
	"github.com/Voskan/codexsentinel/v2/analyzer/result"
)

var sensitiveLogMeta = ruleMeta{ID: "sensitive-data-in-logs", Title: "Sensitive Data in Logs", Severity: result.SeverityHigh, CWE: "CWE-532", OWASP: "A09:2025", Confidence: 0.85,
	Suggestion: "Never log credentials or personal data; log a redacted form, or give the type a log representation (slog.LogValuer, zapcore.ObjectMarshaler, zerolog.LogObjectMarshaler) that omits sensitive fields.",
	References: []string{"https://cwe.mitre.org/data/definitions/532.html", "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"}}

type loggerKind int

const (
	loggerSlog loggerKind = iota
	loggerZap
	loggerZapReflect
	loggerZerolog
	loggerFmt
)

// logArg is a value handed to a logger, with the key it is logged under.
type logArg struct {
	key  string
	expr ast.Expr
}

// RegisterLoggingMonitoringRule reports credentials and personal data passed
// to log/slog, zap, zerolog and the standard log package.
func RegisterLoggingMonitoringRule(ctx *analyzer.AnalyzerContext) {
	registerRules(ctx, []ruleMeta{sensitiveLogMeta}, func(r *reporter) {
		info := r.pass.TypesInfo
		for _, file := range r.pass.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				kind, args, ok := loggerArgs(info, call)
				if !ok {
					return true
				}
				for _, arg := range args {
					checkLogArg(r, info, kind, arg)
				}
				return true
			})
		}
	})
}

var (
	slogLevels    = []string{"Info", "Warn", "Error", "Debug"}
	slogCtxLevels = []string{"InfoContext", "WarnContext", "ErrorContext", "DebugContext"}
	zapFields     = []string{"Any", "String", "Stringer", "ByteString", "Strings", "Reflect"}
	sugarKV       = []string{"Infow", "Warnw", "Errorw", "Debugw", "DPanicw", "Panicw", "Fatalw", "With"}
	sugarArgs     = []string{"Info", "Warn", "Error", "Debug", "DPanic", "Panic", "Fatal", "Infoln", "Warnln", "Errorln", "Debugln"}
	sugarFormat   = []string{"Infof", "Warnf", "Errorf", "Debugf", "DPanicf", "Panicf", "Fatalf"}
	zerologFields = []string{"Interface", "Any", "Str", "Strs", "Bytes", "Stringer", "RawJSON"}
	stdArgs       = []string{"Print", "Println", "Fatal", "Fatalln", "Panic", "Panicln"}
	stdFormat     = []string{"Printf", "Fatalf", "Panicf"}
)

const (
	zapPkg     = "go.uber.org/zap"
	zerologPkg = "github.com/rs/zerolog"
)

// loggerArgs returns the logged values of a logging call, skipping message text.
func loggerArgs(info *types.Info, call *ast.CallExpr) (loggerKind, []logArg, bool) {
	fn := calleeFunc(info, call)
	if fn == nil || fn.Pkg() == nil {
		return 0, nil, false
	}
	l := logCall{info: info, fn: fn, args: call.Args}
	switch fn.Pkg().Path() {
	case "log/slog":
		return l.slog()
	case zapPkg:
		return l.zap()
	case zerologPkg:
		return l.zerolog()
	case "log":
		return l.std()
	}
	return 0, nil, false
}

// logCall is a call into a logging package.
type logCall struct {
	info *types.Info
	fn   *types.Func
	args []ast.Expr
}

// from returns the arguments starting at index i.
func (l logCall) from(i int) []ast.Expr {
	if i >= len(l.args) {
		return nil
	}
	return l.args[i:]
}

// field returns the value of a (key, value) field constructor.
func (l logCall) field() []logArg {
	return []logArg{{key: constKey(l.info, l.args[0]), expr: l.args[1]}}
}

func (l logCall) slog() (loggerKind, []logArg, bool) {
	name := l.fn.Name()
	switch {
	case nameIn(name, slogLevels):
		return loggerSlog, keyValues(l.info, l.from(1)), true
	case nameIn(name, slogCtxLevels):
		return loggerSlog, keyValues(l.info, l.from(2)), true
	case name == "Log" || name == "LogAttrs":
		return loggerSlog, keyValues(l.info, l.from(3)), true
	case name == "With":
		return loggerSlog, keyValues(l.info, l.args), true
	case recvOf(l.fn) == nil && nameIn(name, []string{"Any", "String"}) && len(l.args) == 2:
		return loggerSlog, l.field(), true
	}
	return 0, nil, false
}

func (l logCall) zap() (loggerKind, []logArg, bool) {
	name := l.fn.Name()
	if recvOf(l.fn) == nil {
		if !nameIn(name, zapFields) || len(l.args) != 2 {
			return 0, nil, false
		}
		if name == "Reflect" {
			return loggerZapReflect, l.field(), true
		}
		return loggerZap, l.field(), true
	}
	if !isMethod(l.fn, zapPkg, "SugaredLogger") {
		return 0, nil, false
	}
	switch {
	case name == "With":
		return loggerZap, keyValues(l.info, l.args), true
	case nameIn(name, sugarKV):
		return loggerZap, keyValues(l.info, l.from(1)), true
	case nameIn(name, sugarArgs):
		return loggerFmt, plainValues(l.args), true
	case nameIn(name, sugarFormat) && len(l.args) > 0:
		return loggerFmt, formatValues(l.info, l.args[0], l.from(1)), true
	}
	return 0, nil, false
}

func (l logCall) zerolog() (loggerKind, []logArg, bool) {
	switch {
	case (isMethod(l.fn, zerologPkg, "Event") || isMethod(l.fn, zerologPkg, "Context")) && nameIn(l.fn.Name(), zerologFields) && len(l.args) == 2:
		return loggerZerolog, l.field(), true
	case isMethod(l.fn, zerologPkg, "Event", "Msgf") && len(l.args) > 0:
		return loggerFmt, formatValues(l.info, l.args[0], l.from(1)), true
	}
	return 0, nil, false
}

func (l logCall) std() (loggerKind, []logArg, bool) {
	switch {
	case nameIn(l.fn.Name(), stdArgs):
		return loggerFmt, plainValues(l.args), true
	case nameIn(l.fn.Name(), stdFormat) && len(l.args) > 0:
		return loggerFmt, formatValues(l.info, l.args[0], l.from(1)), true
	}
	return 0, nil, false
}

func constKey(info *types.Info, e ast.Expr) string {
	s, _ := constString(info, e)
	return s
}

// keyValues pairs alternating key/value arguments; attribute values are skipped
// because their constructors are checked on their own.
func keyValues(info *types.Info, args []ast.Expr) []logArg {
	var out []logArg
	for i := 0; i < len(args); i++ {
		if key, ok := constString(info, args[i]); ok && i+1 < len(args) {
			out = append(out, logArg{key: key, expr: args[i+1]})
			i++
			continue
		}
		t := typeOf(info, args[i])
		if typeIs(t, "log/slog", "Attr") || typeIs(t, zapPkg, "Field") || typeIs(t, "go.uber.org/zap/zapcore", "Field") {
			continue
		}
		out = append(out, logArg{expr: args[i]})
	}
	return out
}

func plainValues(args []ast.Expr) []logArg {
	out := make([]logArg, 0, len(args))
	for _, a := range args {
		out = append(out, logArg{expr: a})
	}
	return out
}

var (
	formatVerb = regexp.MustCompile(`%[-+# 0-9.*\[\]]*[a-zA-Z%]`)
	formatKey  = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_\-]*)\s*["']?\s*[=:]\s*["']?\s*$`)
)

// formatValues pairs printf arguments with the label preceding their verb,
// e.g. "token=%s" labels its argument "token".
func formatValues(info *types.Info, format ast.Expr, args []ast.Expr) []logArg {
	out := plainValues(args)
	f, ok := constString(info, format)
	if !ok {
		return out
	}
	prev, i := 0, 0
	for _, loc := range formatVerb.FindAllStringIndex(f, -1) {
		if f[loc[0]:loc[1]] == "%%" {
			continue
		}
		if i < len(out) {
			if m := formatKey.FindStringSubmatch(f[prev:loc[0]]); m != nil {
				out[i].key = m[1]
			}
		}
		prev, i = loc[1], i+1
	}
	return out
}

var (
	sensitiveWords = map[string]bool{
		"password": true, "passwd": true, "pwd": true, "passphrase": true, "secret": true, "cvv": true, "cvc": true,
		"ssn": true, "pin": true, "bearer": true, "authorization": true, "credentials": true,
		"apikey": true, "accesstoken": true, "refreshtoken": true, "idtoken": true, "privatekey": true,
		"creditcard": true, "cardnumber": true, "clientsecret": true, "authtoken": true, "apitoken": true, "sessiontoken": true,
	}
	sensitivePairs = map[[2]string]bool{
		{"api", "key"}: true, {"access", "token"}: true, {"refresh", "token"}: true, {"id", "token"}: true,
		{"private", "key"}: true, {"credit", "card"}: true, {"card", "number"}: true, {"client", "secret"}: true,
		{"auth", "token"}: true, {"api", "token"}: true, {"session", "token"}: true, {"secret", "key"}: true,
		{"social", "security"}: true,
	}
	// Names ending in these words describe a secret without containing it.
	sensitiveMeta = map[string]bool{
		"type": true, "name": true, "len": true, "length": true, "hash": true, "hashed": true, "set": true, "ok": true,
		"present": true, "valid": true, "invalid": true, "count": true, "policy": true, "rule": true, "rules": true,
		"expiry": true, "expires": true, "expiration": true, "at": true, "ttl": true, "id": true, "url": true,
		"path": true, "file": true, "env": true, "field": true, "error": true, "err": true, "changed": true,
		"reset": true, "updated": true, "required": true, "enabled": true, "strength": true, "mask": true,
		"masked": true, "redacted": true, "last4": true, "prefix": true, "hint": true, "header": true, "version": true,
	}
	redactionCall = regexp.MustCompile(`(?i)redact|mask|hash|obfusc|saniti[sz]|scrub|censor|anonymi|truncat|last4|hide|fingerprint`)
)

// sensitiveName reports whether an identifier or log key names a credential or
// personal datum.
func sensitiveName(name string) bool {
	words := splitWords(name)
	if len(words) == 0 || sensitiveMeta[words[len(words)-1]] {
		return false
	}
	for i, w := range words {
		if sensitiveWords[w] {
			return true
		}
		if i+1 < len(words) && sensitivePairs[[2]string{w, words[i+1]}] {
			return true
		}
	}
	return false
}

// valueName returns the name that describes a logged expression.
func valueName(info *types.Info, e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	case *ast.StarExpr:
		return valueName(info, x.X)
	case *ast.UnaryExpr:
		return valueName(info, x.X)
	case *ast.ParenExpr:
		return valueName(info, x.X)
	case *ast.CallExpr:
		fn := calleeFunc(info, x)
		if len(x.Args) == 1 && (isMethod(fn, "net/http", "Header", "Get", "Values") || isMethod(fn, "net/http", "Request", "FormValue", "PostFormValue") ||
			isMethod(fn, "net/url", "Values", "Get") || isFunc(fn, "os", "Getenv")) {
			return constKey(info, x.Args[0])
		}
		if tv, ok := info.Types[x.Fun]; ok && tv.IsType() && len(x.Args) == 1 {
			return valueName(info, x.Args[0])
		}
	}
	return ""
}

func checkLogArg(r *reporter, info *types.Info, kind loggerKind, arg logArg) {
	e := ast.Unparen(arg.expr)
	if isConst(info, e) {
		return
	}
	t := typeOf(info, e)
	if t == nil {
		return
	}
	if named, field := sensitiveStruct(t, 0); named != nil {
		if iface, hidden := logRepresentation(r.pass.Pkg, kind, named); !hidden {
			r.report(sensitiveLogMeta, arg.expr, fmt.Sprintf("Struct '%s' passed to logger exposes sensitive field '%s'. Implement %s (or omit the struct) to prevent credential leakage in logs.", named.Obj().Name(), field, iface))
		}
		return
	}
	if b, ok := t.Underlying().(*types.Basic); ok && b.Info()&types.IsBoolean != 0 {
		return
	}
	if types.Identical(t, types.Universe.Lookup("error").Type()) {
		return
	}
	if call, ok := e.(*ast.CallExpr); ok {
		if fn := calleeFunc(info, call); fn != nil && redactionCall.MatchString(fn.Name()) {
			return
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "len" {
			return
		}
	}
	label := ""
	switch name := valueName(info, e); {
	case arg.key != "" && sensitiveName(arg.key):
		label = arg.key
	case name != "" && sensitiveName(name):
		label = name
	default:
		return
	}
	r.report(sensitiveLogMeta, arg.expr, fmt.Sprintf("Sensitive value '%s' is passed to the logger; redact or omit it to prevent credential leakage in logs.", label))
}

// sensitiveStruct returns the named struct type of t (or *t) and the path of
// an exported sensitive field that serialization would expose.
func sensitiveStruct(t types.Type, depth int) (*types.Named, string) {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok {
		return nil, ""
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok || depth > 2 {
		return nil, ""
	}
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if !f.Exported() {
			continue
		}
		tag := reflect.StructTag(st.Tag(i))
		if tag.Get("json") == "-" || tag.Get("log") == "-" || tag.Get("slog") == "-" {
			continue
		}
		jsonName, _, _ := strings.Cut(tag.Get("json"), ",")
		if !f.Embedded() && (sensitiveName(f.Name()) || jsonName != "" && sensitiveName(jsonName)) {
			if b, ok := f.Type().Underlying().(*types.Basic); !ok || b.Info()&types.IsBoolean == 0 {
				return named, f.Name()
			}
		}
		if _, inner := sensitiveStruct(f.Type(), depth+1); inner != "" {
			if f.Embedded() {
				return named, inner
			}
			return named, f.Name() + "." + inner
		}
	}
	return nil, ""
}

// logRepresentation reports whether named controls how the given logger
// renders it, and otherwise names the interface it should implement.
func logRepresentation(pkg *types.Package, kind loggerKind, named *types.Named) (string, bool) {
	switch kind {
	case loggerSlog:
		return "slog.LogValuer", implementsNamed(pkg, named, "log/slog", "LogValuer", "LogValue")
	case loggerZap:
		return "zapcore.ObjectMarshaler", implementsNamed(pkg, named, "go.uber.org/zap/zapcore", "ObjectMarshaler", "MarshalLogObject") ||
			implementsNamed(pkg, named, "fmt", "Stringer", "String")
	case loggerZapReflect:
		return "json.Marshaler", implementsNamed(pkg, named, "encoding/json", "Marshaler", "MarshalJSON")
	case loggerZerolog:
		return "zerolog.LogObjectMarshaler", implementsNamed(pkg, named, zerologPkg, "LogObjectMarshaler", "MarshalZerologObject") ||
			implementsNamed(pkg, named, "encoding/json", "Marshaler", "MarshalJSON")
	default:
		return "fmt.Stringer", implementsNamed(pkg, named, "fmt", "Stringer", "String") || implementsNamed(pkg, named, "fmt", "Formatter", "Format") ||
			implementsNamed(pkg, named, "fmt", "GoStringer", "GoString")
	}
}

// implementsNamed reports whether named or *named implements the interface
// path.iface. When the interface's package is not among the dependencies of
// pkg, it falls back to looking up the method by name.
func implementsNamed(pkg *types.Package, named *types.Named, path, iface, method string) bool {
	if it := lookupInterface(pkg, path, iface); it != nil {
		return types.Implements(named, it) || types.Implements(types.NewPointer(named), it)
	}
	obj, _, _ := types.LookupFieldOrMethod(types.NewPointer(named), true, named.Obj().Pkg(), method)
	_, ok := obj.(*types.Func)
	return ok
}

func lookupInterface(pkg *types.Package, path, name string) *types.Interface {
	if pkg == nil {
		return nil
	}
	seen := map[*types.Package]bool{}
	var walk func(p *types.Package) *types.Interface
	walk = func(p *types.Package) *types.Interface {
		if seen[p] {
			return nil
		}
		seen[p] = true
		if p.Path() == path {
			if obj, ok := p.Scope().Lookup(name).(*types.TypeName); ok {
				if it, ok := obj.Type().Underlying().(*types.Interface); ok {
					return it
				}
			}
			return nil
		}
		for _, imp := range p.Imports() {
			if it := walk(imp); it != nil {
				return it
			}
		}
		return nil
	}
	return walk(pkg)
}
