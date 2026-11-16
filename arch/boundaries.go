package arch

import (
	"fmt"
	"go/token"
	"go/types"
	"sort"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer/workspace"
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
		noTransport, noDatabase := transportFree[layer], databaseFree[layer]
		if !noTransport && !noDatabase {
			continue
		}
		qual := types.RelativeTo(pkg.Types)
		check := func(t types.Type, object string, pos token.Pos) {
			seen := map[types.Type]bool{}
			var offending types.Type
			kind := ""
			var walk func(types.Type)
			walk = func(t types.Type) {
				if t == nil || seen[t] || offending != nil {
					return
				}
				seen[t] = true
				switch x := t.(type) {
				case *types.Named:
					if obj := x.Obj(); obj.Pkg() != nil {
						switch path := obj.Pkg().Path(); {
						case noTransport && matchesPackage(path, transportPackages):
							offending, kind = t, "Transport"
							return
						case noDatabase && matchesPackage(path, databasePackages):
							offending, kind = t, "Database"
							return
						}
					}
					for i := 0; i < x.TypeArgs().Len(); i++ {
						walk(x.TypeArgs().At(i))
					}
				case *types.Alias:
					walk(types.Unalias(x))
				case *types.Pointer:
					walk(x.Elem())
				case *types.Slice:
					walk(x.Elem())
				case *types.Array:
					walk(x.Elem())
				case *types.Map:
					walk(x.Key())
					walk(x.Elem())
				case *types.Chan:
					walk(x.Elem())
				case *types.Signature:
					for i := 0; i < x.Params().Len(); i++ {
						walk(x.Params().At(i).Type())
					}
					for i := 0; i < x.Results().Len(); i++ {
						walk(x.Results().At(i).Type())
					}
				}
			}
			walk(t)
			if offending == nil {
				return
			}
			// Report the outermost form when the parameter itself is the type (e.g. *http.Request).
			shown := offending
			if p, ok := t.(*types.Pointer); ok && types.Identical(p.Elem(), offending) {
				shown = t
			}
			out = append(out, BoundaryLeak{Layer: layer, Kind: kind, Type: types.TypeString(shown, qualifierWithPkg(qual)), Object: object, PkgPath: pkg.PkgPath, Pos: ws.Fset.Position(pos)})
		}
		checkSignature := func(sig *types.Signature, object string, pos token.Pos) {
			for i := 0; i < sig.Params().Len(); i++ {
				p := sig.Params().At(i)
				check(p.Type(), object, p.Pos())
			}
			for i := 0; i < sig.Results().Len(); i++ {
				check(sig.Results().At(i).Type(), object, pos)
			}
		}
		scope := pkg.Types.Scope()
		for _, name := range scope.Names() {
			switch obj := scope.Lookup(name).(type) {
			case *types.Func:
				checkSignature(obj.Type().(*types.Signature), name, obj.Pos())
			case *types.Var:
				check(obj.Type(), name, obj.Pos())
			case *types.TypeName:
				named, ok := obj.Type().(*types.Named)
				if !ok {
					continue
				}
				switch u := named.Underlying().(type) {
				case *types.Struct:
					for i := 0; i < u.NumFields(); i++ {
						f := u.Field(i)
						check(f.Type(), name+"."+f.Name(), f.Pos())
					}
				case *types.Interface:
					for i := 0; i < u.NumExplicitMethods(); i++ {
						m := u.ExplicitMethod(i)
						checkSignature(m.Type().(*types.Signature), name+"."+m.Name(), m.Pos())
					}
				}
				for i := 0; i < named.NumMethods(); i++ {
					m := named.Method(i)
					checkSignature(m.Type().(*types.Signature), name+"."+m.Name(), m.Pos())
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Pos.Filename != out[j].Pos.Filename {
			return out[i].Pos.Filename < out[j].Pos.Filename
		}
		return out[i].Pos.Offset < out[j].Pos.Offset
	})
	return out
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
