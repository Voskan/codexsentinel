package yaml

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"reflect"
	"regexp"
	"strings"
)

const (
	metaPrefix = "__codex_var_"
	ellipsis   = "__codex_ellipsis"
)

var (
	dollarVar   = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)`)
	mustacheVar = regexp.MustCompile(`\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)
	bareDots    = regexp.MustCompile(`([(,]\s*)\.\.\.(\s*[,)])`)
)

// Pattern is a compiled Go code template. Metavariables ($X, {{x}}) match any
// expression or identifier; $... matches any number of call arguments.
type Pattern struct {
	Source string
	node   ast.Node
}

// prepare rewrites metavariable syntax into valid Go identifiers.
func prepare(src string) string {
	src = strings.ReplaceAll(src, "$...", ellipsis)
	src = dollarVar.ReplaceAllString(src, metaPrefix+"$1")
	src = mustacheVar.ReplaceAllString(src, metaPrefix+"$1")
	for bareDots.MatchString(src) {
		src = bareDots.ReplaceAllString(src, "${1}"+ellipsis+"${2}")
	}
	return src
}

// CompilePattern parses a pattern as an expression or, failing that, as a
// single statement.
func CompilePattern(src string) (*Pattern, error) {
	prepared := prepare(strings.TrimSpace(src))
	if prepared == "" {
		return nil, fmt.Errorf("empty pattern")
	}
	if expr, err := parser.ParseExpr(prepared); err == nil {
		return &Pattern{Source: src, node: expr}, nil
	}
	file, err := parser.ParseFile(token.NewFileSet(), "pattern.go", "package p\nfunc __w() {\n"+prepared+"\n}\n", parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("invalid pattern %q: %w", src, err)
	}
	body := file.Decls[0].(*ast.FuncDecl).Body.List
	if len(body) != 1 {
		return nil, fmt.Errorf("invalid pattern %q: expected one expression or statement, got %d statements", src, len(body))
	}
	if es, ok := body[0].(*ast.ExprStmt); ok {
		return &Pattern{Source: src, node: es.X}, nil
	}
	return &Pattern{Source: src, node: body[0]}, nil
}

// Bindings maps metavariable names (without $) to the nodes they matched.
type Bindings map[string]ast.Node

func (b Bindings) clone() Bindings {
	out := make(Bindings, len(b))
	for k, v := range b {
		out[k] = v
	}
	return out
}

// matcher compares pattern trees with candidate trees. With type information,
// a package name in the pattern also matches a renamed import of that package.
type matcher struct {
	info *types.Info
}

// Match reports whether candidate matches the pattern, extending seed.
func (p *Pattern) Match(info *types.Info, candidate ast.Node, seed Bindings) (Bindings, bool) {
	b := seed.clone()
	m := matcher{info: info}
	if !m.match(reflect.ValueOf(p.node), reflect.ValueOf(candidate), b) {
		return nil, false
	}
	return b, true
}

// astEqual reports whether two nodes are structurally identical, ignoring
// positions and comments.
func astEqual(a, b ast.Node) bool {
	m := matcher{}
	return m.match(reflect.ValueOf(a), reflect.ValueOf(b), nil)
}

var (
	posType     = reflect.TypeOf(token.Pos(0))
	objectType  = reflect.TypeOf((*ast.Object)(nil))
	scopeType   = reflect.TypeOf((*ast.Scope)(nil))
	commentType = reflect.TypeOf((*ast.CommentGroup)(nil))
	identType   = reflect.TypeOf((*ast.Ident)(nil))
	exprType    = reflect.TypeOf((*ast.Expr)(nil)).Elem()
)

func metaName(v reflect.Value) (string, bool) {
	if !v.IsValid() || v.Kind() == reflect.Interface && v.IsNil() {
		return "", false
	}
	if v.Kind() == reflect.Interface {
		v = v.Elem()
	}
	if v.Type() != identType || v.IsNil() {
		return "", false
	}
	name := v.Interface().(*ast.Ident).Name
	if strings.HasPrefix(name, metaPrefix) {
		return strings.TrimPrefix(name, metaPrefix), true
	}
	if name == ellipsis {
		return ellipsis, true
	}
	return "", false
}

func (m matcher) match(p, c reflect.Value, b Bindings) bool {
	if b != nil {
		if name, ok := metaName(p); ok && name != ellipsis {
			return bindMeta(name, c, b)
		}
	}
	if p.Kind() == reflect.Interface {
		if p.IsNil() || c.Kind() != reflect.Interface || c.IsNil() {
			return p.IsNil() && (c.Kind() != reflect.Interface || c.IsNil())
		}
		p, c = p.Elem(), c.Elem()
	}
	if p.Type() != c.Type() {
		return false
	}
	switch p.Kind() {
	case reflect.Pointer:
		return m.matchPointer(p, c, b)
	case reflect.Struct:
		return m.matchStruct(p, c, b)
	case reflect.Slice:
		return m.matchList(p, c, b)
	}
	return scalarEqual(p, c)
}

// bindMeta binds metavariable name to the candidate node, or checks that a
// repeated metavariable matches the node bound before.
func bindMeta(name string, c reflect.Value, b Bindings) bool {
	if c.Kind() == reflect.Interface {
		if c.IsNil() {
			return false
		}
		c = c.Elem()
	}
	node, ok := c.Interface().(ast.Node)
	if !ok || reflect.ValueOf(node).IsNil() {
		return false
	}
	if prev, seen := b[name]; seen {
		return astEqual(prev, node)
	}
	b[name] = node
	return true
}

func (m matcher) matchPointer(p, c reflect.Value, b Bindings) bool {
	if p.IsNil() || c.IsNil() {
		return p.IsNil() == c.IsNil()
	}
	if sel, ok := p.Interface().(*ast.SelectorExpr); ok && m.info != nil {
		if csel, ok := c.Interface().(*ast.SelectorExpr); ok && m.packageSelector(sel, csel) {
			return m.match(reflect.ValueOf(sel.Sel), reflect.ValueOf(csel.Sel), b)
		}
	}
	return m.match(p.Elem(), c.Elem(), b)
}

// matchStruct compares the syntax fields of two nodes, ignoring positions,
// comments and resolver objects.
func (m matcher) matchStruct(p, c reflect.Value, b Bindings) bool {
	for i := 0; i < p.NumField(); i++ {
		switch p.Type().Field(i).Type {
		case posType, objectType, scopeType, commentType:
			continue
		}
		if !m.match(p.Field(i), c.Field(i), b) {
			return false
		}
	}
	return true
}

func scalarEqual(p, c reflect.Value) bool {
	switch p.Kind() {
	case reflect.String:
		return p.String() == c.String()
	case reflect.Bool:
		return p.Bool() == c.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return p.Int() == c.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return p.Uint() == c.Uint()
	}
	return reflect.DeepEqual(p.Interface(), c.Interface())
}

// matchList matches slices, letting an ellipsis element absorb any number of
// candidate elements.
func (m matcher) matchList(p, c reflect.Value, b Bindings) bool {
	if p.Len() == 0 {
		return c.Len() == 0
	}
	if b != nil && p.Type().Elem() == exprType {
		if name, ok := metaName(p.Index(0)); ok && name == ellipsis {
			rest := p.Slice(1, p.Len())
			for skip := 0; skip <= c.Len(); skip++ {
				trial := b.clone()
				if m.matchList(rest, c.Slice(skip, c.Len()), trial) {
					for k, v := range trial {
						b[k] = v
					}
					return true
				}
			}
			return false
		}
	}
	if c.Len() == 0 {
		return false
	}
	trial := b
	if b != nil {
		trial = b.clone()
	}
	if !m.match(p.Index(0), c.Index(0), trial) || !m.matchList(p.Slice(1, p.Len()), c.Slice(1, c.Len()), trial) {
		return false
	}
	for k, v := range trial {
		b[k] = v
	}
	return true
}

// packageSelector reports whether pattern pkg.Name and candidate x.Name refer
// to the same package, allowing renamed imports.
func (m matcher) packageSelector(p, c *ast.SelectorExpr) bool {
	pid, ok := p.X.(*ast.Ident)
	if !ok || strings.HasPrefix(pid.Name, metaPrefix) {
		return false
	}
	cid, ok := c.X.(*ast.Ident)
	if !ok {
		return false
	}
	pkgName, ok := m.info.Uses[cid].(*types.PkgName)
	if !ok {
		return false
	}
	imported := pkgName.Imported()
	return imported.Name() == pid.Name || imported.Path() == pid.Name || strings.HasSuffix(imported.Path(), "/"+pid.Name)
}

// FindAll returns every node in root that matches the pattern.
func (p *Pattern) FindAll(info *types.Info, root ast.Node) []Match {
	var out []Match
	wantStmt := false
	if _, ok := p.node.(ast.Stmt); ok {
		wantStmt = true
	}
	ast.Inspect(root, func(n ast.Node) bool {
		switch n.(type) {
		case nil:
			return false
		case ast.Stmt:
			if !wantStmt {
				return true
			}
		case ast.Expr:
			if wantStmt {
				return true
			}
		default:
			return true
		}
		if b, ok := p.Match(info, n, nil); ok {
			out = append(out, Match{Node: n, Bindings: b})
		}
		return true
	})
	return out
}

// Match is one occurrence of a pattern.
type Match struct {
	Node     ast.Node
	Bindings Bindings
}
