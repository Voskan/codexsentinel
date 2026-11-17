package catalog

// moreSecurityDocs covers denial of service, logging, deserialization,
// memory safety and error handling rules.
var moreSecurityDocs = []RuleDoc{
	{
		ID: "http-unbounded-body-read", Code: "CS036", Title: "Unbounded HTTP Request Body Read", Category: CategorySecurity, DefaultSeverity: high,
		CWE: "CWE-400", OWASP: "A06:2025",
		Summary:     "A request body is read completely without a size limit.",
		Explanation: "io.ReadAll(r.Body) and decoders on r.Body read whatever the client sends, so one large request can exhaust memory. http.MaxBytesReader and io.LimitReader bound the read.",
		BadExample:  `body, err := io.ReadAll(r.Body)`,
		GoodExample: `body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))`,
		References:  []string{cweURL + "400.html"},
	},
	{
		ID: "untrusted-slice-allocation", Code: "CS037", Title: "Allocation Sized by Untrusted Input", Category: CategorySecurity, DefaultSeverity: high,
		CWE: "CWE-789", OWASP: "A06:2025",
		Summary:     "make allocates a slice or map whose size comes from the request.",
		Explanation: "A client-supplied count such as ?limit=999999999 makes the server allocate gigabytes before any data is read. Clamp the value first.",
		BadExample: `n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
items := make([]Item, 0, n)`,
		GoodExample: `n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
n = min(max(n, 0), 100)
items := make([]Item, 0, n)`,
		References: []string{cweURL + "789.html"},
	},
	{
		ID: "http-client-unsafe", Code: "CS038", Title: "Unsafe HTTP Client Configuration", Category: CategorySecurity, DefaultSeverity: medium,
		CWE: "CWE-400", OWASP: "A06:2025",
		Summary:     "An HTTP client without a timeout is used, such as http.DefaultClient.",
		Explanation: "Without Client.Timeout or a request context deadline, a slow or malicious server keeps the request, its goroutine and its connection open indefinitely.",
		BadExample:  `resp, err := http.Get(url)`,
		GoodExample: `client := &http.Client{Timeout: 10 * time.Second}
resp, err := client.Get(url)`,
		References: []string{cweURL + "400.html"},
	},
	{
		ID: "context-propagation-missing", Code: "CS039", Title: "Request Context Not Propagated", Category: CategorySecurity, DefaultSeverity: medium,
		CWE: "CWE-400", OWASP: "A06:2025",
		Summary:     "A handler calls a database or network API with context.Background() instead of the request context.",
		Explanation: "When the client disconnects or the deadline passes, work started with context.Background() keeps running and holding connections. Pass r.Context() so cancellation propagates.",
		BadExample:  `rows, err := db.QueryContext(context.Background(), query)`,
		GoodExample: `rows, err := db.QueryContext(r.Context(), query)`,
		References:  []string{"https://go.dev/blog/context"},
	},
	{
		ID: "graphql-unbounded-query", Code: "CS040", Title: "GraphQL Query Complexity Not Limited", Category: CategorySecurity, DefaultSeverity: medium,
		CWE: "CWE-400", OWASP: "A06:2025",
		Summary:     "A GraphQL server has no complexity or depth limit.",
		Explanation: "Nested queries over relations grow exponentially, so a single request can make the server load millions of objects. Set a complexity limit.",
		BadExample:  `srv := handler.NewDefaultServer(es)`,
		GoodExample: `srv := handler.New(es)
srv.Use(extension.FixedComplexityLimit(200))`,
		References: []string{cweURL + "400.html"},
	},
	{
		ID: "grpc-server-missing-limits", Code: "CS041", Title: "gRPC Server Without Resource Limits", Category: CategorySecurity, DefaultSeverity: medium,
		CWE: "CWE-400", OWASP: "A06:2025",
		Summary:     "A gRPC server sets neither stream limits nor an interceptor, or allows very large messages.",
		Explanation: "Without MaxConcurrentStreams or an interceptor enforcing limits, one client can open unlimited streams; a MaxRecvMsgSize above 64 MiB lets a single message exhaust memory. Options built in another function are not judged.",
		BadExample:  `srv := grpc.NewServer(grpc.MaxRecvMsgSize(1 << 30))`,
		GoodExample: `srv := grpc.NewServer(
	grpc.MaxConcurrentStreams(100),
	grpc.MaxRecvMsgSize(4<<20),
	grpc.ChainUnaryInterceptor(rateLimit, auth),
)`,
		References: []string{cweURL + "400.html"},
	},
	{
		ID: "sensitive-data-in-logs", Code: "CS042", Title: "Sensitive Data in Logs", Category: CategorySecurity, DefaultSeverity: high,
		CWE: "CWE-532", OWASP: "A09:2025",
		Summary:     "Passwords, tokens or personal data are written to logs.",
		Explanation: "Logs are copied to many systems with weaker access control than the database. slog, zap, zerolog and log calls are checked for sensitive keys and for structs with sensitive fields; a type that defines its own log representation (slog.LogValuer, zapcore.ObjectMarshaler, zerolog.LogObjectMarshaler) is trusted.",
		BadExample:  `slog.Info("login", "user", req.Email, "password", req.Password)`,
		GoodExample: `slog.Info("login", "user", req.Email)`,
		References:  []string{cweURL + "532.html"},
	},
	{
		ID: "unsafe-gob-decode", Code: "CS043", Title: "Gob Decoding of Untrusted Input", Category: CategorySecurity, DefaultSeverity: high,
		CWE: "CWE-502", OWASP: "A08:2025",
		Summary:     "encoding/gob decodes a request body.",
		Explanation: "gob is meant for trusted peers; crafted streams can allocate excessively or panic the decoder. Use JSON or protobuf with size limits for client data.",
		BadExample:  `err := gob.NewDecoder(r.Body).Decode(&msg)`,
		GoodExample: `err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&msg)`,
		References:  []string{cweURL + "502.html"},
	},
	{
		ID: "unsafe-memory-manipulation", Code: "CS044", Title: "Unsafe Memory Manipulation", Category: CategorySecurity, DefaultSeverity: high,
		CWE: "CWE-119", OWASP: "A06:2025",
		Summary:     "reflect.SliceHeader, a uintptr kept across statements, or unsafe.Slice with an unchecked length.",
		Explanation: "The garbage collector does not treat a uintptr as a reference: a pointer stored as uintptr and converted back later may point to moved or freed memory. reflect.SliceHeader and StringHeader are deprecated for the same reason. unsafe.Slice with an unchecked length reads or writes past the allocation. Pointer arithmetic in one expression with unsafe.Add is fine.",
		BadExample: `addr := uintptr(unsafe.Pointer(h))
return (*int64)(unsafe.Pointer(addr + 8))`,
		GoodExample: `return (*int64)(unsafe.Add(unsafe.Pointer(h), 8))`,
		References:  []string{"https://pkg.go.dev/unsafe#Pointer", cweURL + "119.html"},
	},
	{
		ID: "security-err-ignored", Code: "CS045", Title: "Security-Critical Error Ignored", Category: CategorySecurity, DefaultSeverity: high,
		CWE: "CWE-252", OWASP: "A10:2025",
		Summary:     "The error of a call whose failure leaves the program insecure is dropped.",
		Explanation: "Only a short list of calls is checked: random reads (a failed crypto/rand.Read leaves a zero key), bcrypt.CompareHashAndPassword (ignoring it accepts any password), TLS handshakes, certificate verification, permission and privilege changes, and rows.Err after iterating query results. Ignored errors of other calls are not reported.",
		BadExample: `key := make([]byte, 32)
rand.Read(key)`,
		GoodExample: `key := make([]byte, 32)
if _, err := rand.Read(key); err != nil {
	return nil, err
}`,
		References: []string{cweURL + "252.html"},
	},
	{
		ID: "template-injection", Code: "CS084", Title: "Template Injection", Category: CategorySecurity, DefaultSeverity: high,
		CWE: "CWE-1336", OWASP: "A05:2025",
		Summary: "Template source text is built from untrusted data.",
		Explanation: "Template actions in the parsed text can call any exported method and field of the data passed to Execute, read other templates and, with text/template, write raw markup. " +
			"html/template escapes values, not the template itself, so parsing untrusted text is unsafe with both packages. " +
			"The taint engine reports untrusted data that reaches Template.Parse.",
		BadExample: `func greet(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.New("greet").Parse("<p>Hello " + r.FormValue("name") + "</p>")
	if err != nil {
		return
	}
	_ = tmpl.Execute(w, user)
}`,
		GoodExample: `var greetPage = template.Must(template.New("greet").Parse("<p>Hello {{.}}</p>"))

func greet(w http.ResponseWriter, r *http.Request) {
	_ = greetPage.Execute(w, r.FormValue("name"))
}`,
		References: []string{cweURL + "1336.html", "https://pkg.go.dev/html/template"},
	},
	{
		ID: "nosql-injection", Code: "CS085", Title: "NoSQL Injection", Category: CategorySecurity, DefaultSeverity: high,
		CWE: "CWE-943", OWASP: "A05:2025",
		Summary: "Database-side code is built from untrusted data: a Redis Lua script or MongoDB $where, $function or $accumulator JavaScript.",
		Explanation: "Redis EVAL and MongoDB $where run the given text as code on the database server, so input concatenated into it can read or change any key or document the connection can reach. " +
			"The taint engine follows request data to go-redis Eval, EvalRO, ScriptLoad and NewScript across functions; MongoDB query documents (bson.M, bson.D or a map) are checked within the function that builds them. " +
			"Ordinary filter values such as bson.M{\"name\": name} are not reported: the driver sends them as data.",
		BadExample: `func count(w http.ResponseWriter, r *http.Request) {
	field := r.FormValue("field")
	rdb.Eval(r.Context(), "return redis.call('HGET', KEYS[1], '"+field+"')", []string{"stats"})
	coll.Find(r.Context(), bson.M{"$where": "this.owner == '" + r.FormValue("owner") + "'"})
}`,
		GoodExample: `var hget = redis.NewScript("return redis.call('HGET', KEYS[1], ARGV[1])")

func count(w http.ResponseWriter, r *http.Request) {
	hget.Run(r.Context(), rdb, []string{"stats"}, r.FormValue("field"))
	coll.Find(r.Context(), bson.M{"owner": r.FormValue("owner")})
}`,
		References: []string{cweURL + "943.html", "https://www.mongodb.com/docs/manual/reference/operator/query/where/", "https://redis.io/docs/latest/develop/interact/programmability/eval-intro/"},
	},
}
