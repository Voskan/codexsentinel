package arch

import (
	"go/token"
	"go/types"
	"sort"

	"github.com/Voskan/codexsentinel/analyzer/workspace"
)

// GodStruct is a struct type with too many methods or fields.
type GodStruct struct {
	Name      string
	PkgPath   string
	MethodNum int
	FieldNum  int
	Methods   []string
	Pos       token.Position
}

// AnalyzeGodStructs reports struct types of the analyzed packages, exported or
// not, that declare more than maxMethods methods or maxFields fields.
func AnalyzeGodStructs(ws *workspace.Workspace, maxMethods, maxFields int) []GodStruct {
	if maxMethods <= 0 {
		maxMethods = 15
	}
	if maxFields <= 0 {
		maxFields = 20
	}
	var out []GodStruct
	for _, pkg := range ws.Packages {
		if pkg.Types == nil || len(ws.Files(pkg)) == 0 {
			continue
		}
		scope := pkg.Types.Scope()
		for _, name := range scope.Names() {
			tn, ok := scope.Lookup(name).(*types.TypeName)
			if !ok || tn.IsAlias() {
				continue
			}
			named, ok := tn.Type().(*types.Named)
			if !ok {
				continue
			}
			st, ok := named.Underlying().(*types.Struct)
			if !ok {
				continue
			}
			var methods []string
			for i := 0; i < named.NumMethods(); i++ {
				methods = append(methods, named.Method(i).Name())
			}
			sort.Strings(methods)
			if len(methods) > maxMethods || st.NumFields() > maxFields {
				out = append(out, GodStruct{Name: name, PkgPath: pkg.PkgPath, MethodNum: len(methods), FieldNum: st.NumFields(), Methods: methods, Pos: ws.Fset.Position(tn.Pos())})
			}
		}
	}
	return out
}
