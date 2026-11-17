package arch

import (
	"fmt"
	"go/token"
	"go/types"
	"sort"
	"strings"

	"github.com/Voskan/codexsentinel/v2/analyzer/workspace"
)

// BoundaryLeak is an infrastructure type used in the API of a layer that
// should not know about it.
type BoundaryLeak struct {
	Layer   string
	Kind    string // "Transport" or "Database"
	Type    string // e.g. *http.Request
	Object  string // function, method or field exposing the type
	PkgPath string
	Pos     token.Position
}

// Message renders the leak for reports.
func (b BoundaryLeak) Message() string {
	return fmt.Sprintf("%s type '%s' leaked into %s layer via %s.", b.Kind, b.Type, b.Layer, b.Object)
}

var (
	transportPackages = []string{"net/http", "github.com/gin-gonic/gin", "github.com/labstack/echo", "github.com/gofiber/fiber", "google.golang.org/grpc/codes", "google.golang.org/grpc/status", "google.golang.org/grpc/metadata"}
	databasePackages  = []string{"database/sql", "gorm.io/gorm", "github.com/jackc/pgx", "github.com/jmoiron/sqlx", "go.mongodb.org/mongo-driver", "github.com/redis/go-redis"}

	// Layers that must not see transport types, and layers that must not see database types.
	transportFree = map[string]bool{"domain": true, "entity": true, "model": true, "usecase": true, "application": true, "core": true}
	databaseFree  = map[string]bool{"domain": true, "entity": true, "model": true, "delivery": true, "handler": true, "controller": true, "transport": true, "api": true}
)

func matchesPackage(path string, list []string) bool {
	for _, p := range list {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// AnalyzeBoundaries inspects the exported and unexported API (function
// signatures, methods, struct fields and interface methods) of packages in
// business and delivery layers for transport and database types.
func AnalyzeBoundaries(ws *workspace.Workspace, l *Layering) []BoundaryLeak {
	idx := newModuleIndex(ws)
	var out []BoundaryLeak
	for _, pkg := range ws.Packages {
		if pkg.Types == nil || len(ws.Files(pkg)) == 0 {
			continue
		}
		layer := idx.layer(l, pkg.PkgPath)
		c := &boundaryChecker{
			ws: ws, pkgPath: pkg.PkgPath, layer: layer,
			noTransport: transportFree[layer], noDatabase: databaseFree[layer],
			qual: qualifierWithPkg(types.RelativeTo(pkg.Types)),
		}
		if !c.noTransport && !c.noDatabase {
			continue
		}
		c.checkScope(pkg.Types.Scope())
		out = append(out, c.leaks...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Pos.Filename != out[j].Pos.Filename {
			return out[i].Pos.Filename < out[j].Pos.Filename
		}
		return out[i].Pos.Offset < out[j].Pos.Offset
	})
	return out
}

// boundaryChecker collects the boundary leaks of one package.
type boundaryChecker struct {
	ws                      *workspace.Workspace
	pkgPath, layer          string
	noTransport, noDatabase bool
	qual                    types.Qualifier
	leaks                   []BoundaryLeak
}

func (c *boundaryChecker) checkScope(scope *types.Scope) {
	for _, name := range scope.Names() {
		switch obj := scope.Lookup(name).(type) {
		case *types.Func:
			c.checkSignature(obj.Type().(*types.Signature), name, obj.Pos())
		case *types.Var:
			c.check(obj.Type(), name, obj.Pos())
		case *types.TypeName:
			if named, ok := obj.Type().(*types.Named); ok {
				c.checkNamed(named, name)
			}
		}
	}
}

func (c *boundaryChecker) checkNamed(named *types.Named, name string) {
	switch u := named.Underlying().(type) {
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			f := u.Field(i)
			c.check(f.Type(), name+"."+f.Name(), f.Pos())
		}
	case *types.Interface:
		for i := 0; i < u.NumExplicitMethods(); i++ {
			m := u.ExplicitMethod(i)
			c.checkSignature(m.Type().(*types.Signature), name+"."+m.Name(), m.Pos())
		}
	}
	for i := 0; i < named.NumMethods(); i++ {
		m := named.Method(i)
		c.checkSignature(m.Type().(*types.Signature), name+"."+m.Name(), m.Pos())
	}
}

func (c *boundaryChecker) checkSignature(sig *types.Signature, object string, pos token.Pos) {
	for i := 0; i < sig.Params().Len(); i++ {
		p := sig.Params().At(i)
		c.check(p.Type(), object, p.Pos())
	}
	for i := 0; i < sig.Results().Len(); i++ {
		c.check(sig.Results().At(i).Type(), object, pos)
	}
}

// check records a leak when t mentions a type the layer must not see.
func (c *boundaryChecker) check(t types.Type, object string, pos token.Pos) {
	offending, kind := c.forbidden(t, map[types.Type]bool{})
	if offending == nil {
		return
	}
	// Report the outermost form when the parameter itself is the type (e.g. *http.Request).
	shown := offending
	if p, ok := t.(*types.Pointer); ok && types.Identical(p.Elem(), offending) {
		shown = t
	}
	c.leaks = append(c.leaks, BoundaryLeak{Layer: c.layer, Kind: kind, Type: types.TypeString(shown, c.qual), Object: object, PkgPath: c.pkgPath, Pos: c.ws.Fset.Position(pos)})
}

// forbidden returns the first transport or database type reachable from t.
func (c *boundaryChecker) forbidden(t types.Type, seen map[types.Type]bool) (types.Type, string) {
	if t == nil || seen[t] {
		return nil, ""
	}
	seen[t] = true
	if named, ok := t.(*types.Named); ok {
		if kind := c.forbiddenPackage(named.Obj().Pkg()); kind != "" {
			return t, kind
		}
	}
	for _, inner := range componentTypes(t) {
		if offending, kind := c.forbidden(inner, seen); offending != nil {
			return offending, kind
		}
	}
	return nil, ""
}

func (c *boundaryChecker) forbiddenPackage(pkg *types.Package) string {
	if pkg == nil {
		return ""
	}
	switch path := pkg.Path(); {
	case c.noTransport && matchesPackage(path, transportPackages):
		return "Transport"
	case c.noDatabase && matchesPackage(path, databasePackages):
		return "Database"
	}
	return ""
}

// componentTypes returns the types a composite type is built from.
func componentTypes(t types.Type) []types.Type {
	switch x := t.(type) {
	case *types.Named:
		var out []types.Type
		for i := 0; i < x.TypeArgs().Len(); i++ {
			out = append(out, x.TypeArgs().At(i))
		}
		return out
	case *types.Alias:
		return []types.Type{types.Unalias(x)}
	case *types.Pointer:
		return []types.Type{x.Elem()}
	case *types.Slice:
		return []types.Type{x.Elem()}
	case *types.Array:
		return []types.Type{x.Elem()}
	case *types.Map:
		return []types.Type{x.Key(), x.Elem()}
	case *types.Chan:
		return []types.Type{x.Elem()}
	case *types.Signature:
		var out []types.Type
		for i := 0; i < x.Params().Len(); i++ {
			out = append(out, x.Params().At(i).Type())
		}
		for i := 0; i < x.Results().Len(); i++ {
			out = append(out, x.Results().At(i).Type())
		}
		return out
	}
	return nil
}

// qualifierWithPkg names foreign types by package name (http.Request) and
// local ones without qualification.
func qualifierWithPkg(local types.Qualifier) types.Qualifier {
	return func(p *types.Package) string {
		if local(p) == "" {
			return ""
		}
		return p.Name()
	}
}
