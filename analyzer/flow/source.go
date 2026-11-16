package flow

func httpSource(recv, fn string) SourceSpec {
	return SourceSpec{Package: "net/http", Receiver: recv, Function: fn, Tags: []string{"http"}, Description: "HTTP request data"}
}

func frameworkSources(pkg, recv string, methods []string, outArgMethods []string) []SourceSpec {
	var out []SourceSpec
	for _, m := range methods {
		out = append(out, SourceSpec{Package: pkg, Receiver: recv, Function: m, Tags: []string{"http"}, Description: "HTTP request data"})
	}
	for _, m := range outArgMethods {
		out = append(out, SourceSpec{Package: pkg, Receiver: recv, Function: m, Kind: SourceOutArg, OutArgs: []int{0}, Tags: []string{"http"}, Description: "decoded HTTP request body"})
	}
	return out
}

// builtinSources lists untrusted inputs from HTTP requests, popular web
// frameworks, gRPC and ConnectRPC handlers, the command line and the
// environment.
func builtinSources() []SourceSpec {
	var out []SourceSpec
	for _, m := range []string{"FormValue", "PostFormValue", "PathValue", "Cookie", "Cookies", "CookiesNamed", "Referer", "UserAgent", "FormFile", "MultipartReader", "BasicAuth"} {
		out = append(out, httpSource("Request", m))
	}
	for _, f := range []string{"URL", "Header", "Body", "Form", "PostForm", "MultipartForm", "RequestURI", "Host", "Trailer"} {
		s := httpSource("Request", f)
		s.Kind = SourceField
		out = append(out, s)
	}
	out = append(out, SourceSpec{Package: "net/url", Receiver: "Values", Function: "Get", Tags: []string{"http"}, Description: "URL query parameter"})

	ginBind := []string{"Bind", "BindJSON", "BindQuery", "BindUri", "BindXML", "BindYAML", "BindHeader", "ShouldBind", "ShouldBindJSON", "ShouldBindQuery", "ShouldBindUri", "ShouldBindXML", "ShouldBindYAML", "ShouldBindHeader", "ShouldBindWith", "ShouldBindBodyWith"}
	out = append(out, frameworkSources("github.com/gin-gonic/gin", "Context",
		[]string{"Query", "DefaultQuery", "GetQuery", "QueryArray", "QueryMap", "Param", "PostForm", "DefaultPostForm", "GetPostForm", "PostFormArray", "PostFormMap", "GetHeader", "GetRawData", "Cookie", "FormFile", "ClientIP"}, ginBind)...)
	out = append(out, frameworkSources("github.com/labstack/echo/v4", "Context",
		[]string{"QueryParam", "QueryParams", "QueryString", "Param", "ParamValues", "FormValue", "FormParams", "FormFile", "Cookie", "Cookies"}, []string{"Bind"})...)
	out = append(out, frameworkSources("github.com/gofiber/fiber/v2", "Ctx",
		[]string{"Params", "Query", "Queries", "Body", "BodyRaw", "Get", "Cookies", "FormValue", "FormFile", "OriginalURL", "Path"}, []string{"BodyParser", "QueryParser", "ParamsParser", "ReqHeaderParser", "CookieParser"})...)
	out = append(out,
		SourceSpec{Package: "github.com/go-chi/chi/v5", Function: "URLParam", Tags: []string{"http"}, Description: "chi URL parameter"},
		SourceSpec{Package: "github.com/go-chi/chi", Function: "URLParam", Tags: []string{"http"}, Description: "chi URL parameter"},
		SourceSpec{Package: "github.com/gorilla/mux", Function: "Vars", Tags: []string{"http"}, Description: "gorilla/mux route variables"},
	)

	cli := []string{"cli"}
	out = append(out,
		SourceSpec{Package: "os", Function: "Args", Kind: SourceGlobal, Tags: cli, Confidence: 0.7, Description: "command-line arguments"},
		SourceSpec{Package: "os", Function: "Stdin", Kind: SourceGlobal, Tags: cli, Confidence: 0.7, Description: "standard input"},
		SourceSpec{Package: "fmt", Function: "Scan", Kind: SourceOutArg, OutArgs: []int{0}, Tags: cli, Confidence: 0.7, Description: "standard input"},
		SourceSpec{Package: "fmt", Function: "Scanln", Kind: SourceOutArg, OutArgs: []int{0}, Tags: cli, Confidence: 0.7, Description: "standard input"},
		SourceSpec{Package: "fmt", Function: "Scanf", Kind: SourceOutArg, OutArgs: []int{1}, Tags: cli, Confidence: 0.7, Description: "standard input"},
		SourceSpec{Package: "os", Function: "Getenv", Tags: []string{"env"}, Confidence: 0.6, Description: "environment variable"},
		SourceSpec{Package: "os", Function: "LookupEnv", Tags: []string{"env"}, Confidence: 0.6, Description: "environment variable"},
	)
	return append(out, rpcSources()...)
}
