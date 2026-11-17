package flow_test

import (
	"testing"

	"github.com/Voskan/codexsentinel/analyzer/flow"
	"github.com/Voskan/codexsentinel/analyzer/testutil"
)

func TestTemplateInjection(t *testing.T) {
	testutil.RunTaintBothModes(t, map[string]string{"app.go": `package app

import (
	htmltemplate "html/template"
	"net/http"
	"text/template"
)

var page = htmltemplate.Must(htmltemplate.New("page").Parse("<p>{{.}}</p>"))

func greet(w http.ResponseWriter, r *http.Request) {
	tmpl, _ := template.New("t").Parse("Hello " + r.FormValue("name")) // want "template-injection"
	_ = tmpl.Execute(w, nil)
	safe, _ := htmltemplate.New("t").Parse(r.FormValue("layout")) // want "template-injection"
	_ = safe.Execute(w, nil)
	_ = page.Execute(w, r.FormValue("name"))
}
`}, flow.DefaultRegistry())
}

func TestRedisScriptInjection(t *testing.T) {
	testutil.RunTaintBothModes(t, map[string]string{
		"go.mod":             "module example.com/fixture\n\ngo 1.24\n\nrequire github.com/redis/go-redis/v9 v9.0.0\n\nreplace github.com/redis/go-redis/v9 => ./stubs/redis\n",
		"stubs/redis/go.mod": "module github.com/redis/go-redis/v9\n\ngo 1.24\n",
		"stubs/redis/redis.go": `package redis

import "context"

type Cmd struct{}

type cmdable func(ctx context.Context, cmd *Cmd) error

func (c cmdable) Eval(ctx context.Context, script string, keys []string, args ...interface{}) *Cmd {
	return nil
}

type Client struct{ cmdable }

type UniversalClient interface {
	Eval(ctx context.Context, script string, keys []string, args ...interface{}) *Cmd
}

type Script struct{ src string }

func NewScript(src string) *Script { return &Script{src: src} }
`,
		"app.go": `package app

import (
	"context"
	"net/http"

	"github.com/redis/go-redis/v9"
)

const incr = "return redis.call('INCRBY', KEYS[1], ARGV[1])"

var (
	rdb *redis.Client
	uc  redis.UniversalClient
)

func handler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()
	field := r.FormValue("field")
	rdb.Eval(ctx, "return redis.call('GET', '"+field+"')", nil) // want "nosql-injection"
	uc.Eval(ctx, r.FormValue("script"), nil)                    // want "nosql-injection"
	_ = redis.NewScript("return " + field)                      // want "nosql-injection"
	rdb.Eval(ctx, incr, []string{field}, r.FormValue("n"))
}
`}, flow.DefaultRegistry())
}
