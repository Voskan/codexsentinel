package builtin

import (
	"go/ast"
	"go/types"

	"github.com/Voskan/codexsentinel/analyzer"
	"github.com/Voskan/codexsentinel/analyzer/result"
)

var noSQLMeta = ruleMeta{
	ID: "nosql-injection", Title: "NoSQL Injection", Severity: result.SeverityHigh, CWE: "CWE-943", OWASP: "A05:2025",
	Confidence: 0.8,
	Suggestion: "Do not build server-side JavaScript from request data; express the condition with query operators ($eq, $gt, $in) and pass the input as a value.",
	References: []string{"https://cwe.mitre.org/data/definitions/943.html", "https://www.mongodb.com/docs/manual/reference/operator/query/where/"},
}

// mongoCodeOperators run JavaScript on the database server.
var mongoCodeOperators = map[string]bool{"$where": true, "$function": true, "$accumulator": true}

// RegisterNoSQLInjectionRule reports MongoDB query documents whose $where,
// $function or $accumulator JavaScript is built from HTTP request input in
// the same function. Redis Lua scripts are covered by the taint engine.
func RegisterNoSQLInjectionRule(ctx *analyzer.AnalyzerContext) {
	registerRules(ctx, []ruleMeta{noSQLMeta}, func(r *reporter) {
		info := r.pass.TypesInfo
		for _, file := range r.pass.Files {
			for _, unit := range funcUnits(file) {
				var lt *localTaint
				inspectShallow(unit.Body, func(n ast.Node) bool {
					lit, ok := n.(*ast.CompositeLit)
					if !ok {
						return true
					}
					op, value := mongoCodeElement(info, lit)
					if value == nil {
						return true
					}
					if lt == nil {
						lt = newLocalTaint(info, unit.Body)
					}
					if lt.tainted(value, noSQLMeta.ID) {
						r.report(noSQLMeta, value, "MongoDB "+op+" runs JavaScript built from HTTP request input on the database server.")
					}
					return true
				})
			}
		}
	})
}

// mongoCodeElement returns the operator and value of a query document element
// that runs JavaScript: a map entry keyed "$where" (bson.M or any map with
// string keys) or a bson.E with that Key, written with or without field names.
func mongoCodeElement(info *types.Info, lit *ast.CompositeLit) (string, ast.Expr) {
	t := typeOf(info, lit)
	if t == nil {
		return "", nil
	}
	if isBSONElement(t) {
		var key, value ast.Expr
		for i, elt := range lit.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "Key" {
					key = kv.Value
				} else if ok && id.Name == "Value" {
					value = kv.Value
				}
			} else if i == 0 {
				key = elt
			} else if i == 1 {
				value = elt
			}
		}
		if key == nil || value == nil {
			return "", nil
		}
		if op, ok := constString(info, key); ok && mongoCodeOperators[op] {
			return op, value
		}
		return "", nil
	}
	if _, ok := t.Underlying().(*types.Map); !ok {
		return "", nil
	}
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if op, ok := constString(info, kv.Key); ok && mongoCodeOperators[op] {
				return op, kv.Value
			}
		}
	}
	return "", nil
}

// isBSONElement reports whether t is the bson.E document element of the
// MongoDB Go driver, version 1 (an alias of primitive.E) or version 2.
func isBSONElement(t types.Type) bool {
	pkg, name := namedOf(t)
	if name != "E" {
		return false
	}
	switch pkg {
	case "go.mongodb.org/mongo-driver/bson", "go.mongodb.org/mongo-driver/bson/primitive", "go.mongodb.org/mongo-driver/v2/bson":
		return true
	}
	return false
}
