package builtin

import (
	"testing"

	"github.com/Voskan/codexsentinel/v2/analyzer/testutil"
)

func TestNoSQLInjectionMongoJavaScript(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, map[string]string{
		"go.mod":                   "module example.com/fixture\n\ngo 1.24\n\nrequire go.mongodb.org/mongo-driver v1.0.0\n\nreplace go.mongodb.org/mongo-driver => ./stubs/mongo\n",
		"stubs/mongo/go.mod":       "module go.mongodb.org/mongo-driver\n\ngo 1.24\n",
		"stubs/mongo/bson/bson.go": "package bson\n\nimport \"go.mongodb.org/mongo-driver/bson/primitive\"\n\ntype M = primitive.M\ntype D = primitive.D\ntype E = primitive.E\n",
		"stubs/mongo/bson/primitive/primitive.go": "package primitive\n\ntype M map[string]interface{}\ntype E struct {\n\tKey   string\n\tValue interface{}\n}\ntype D []E\n",
		"app.go": `package app

import (
	"fmt"
	"net/http"
	"strconv"

	"go.mongodb.org/mongo-driver/bson"
)

func find(filter interface{}) {}

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	find(bson.M{"$where": "this.name == '" + name + "'"})                  // want "nosql-injection"
	find(bson.D{{Key: "$where", Value: fmt.Sprintf("this.n > %s", name)}}) // want "nosql-injection"
	find(bson.D{{"$where", "this.owner == '" + r.FormValue("owner") + "'"}}) // want "nosql-injection"
	find(map[string]interface{}{"$function": bson.M{"body": name, "lang": "js"}}) // want "nosql-injection"
	find(bson.M{"name": name})
	find(bson.M{"$where": "this.active"})
	n, _ := strconv.Atoi(r.FormValue("n"))
	find(bson.M{"$where": "this.n > " + strconv.Itoa(n)})
}
`}, RegisterNoSQLInjectionRule)
}
