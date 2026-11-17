package catalog

import "github.com/Voskan/codexsentinel/analyzer/result"

// Categories of the pattern rules embedded from assets/rules.
const (
	CategoryStyle       = "style"
	CategoryCorrectness = "correctness"
)

const info = result.SeverityInfo

// yamlDocs covers the pattern rules embedded in the binary from assets/rules.
// They run in every scan unless disabled, like the built-in rules.
var yamlDocs = []RuleDoc{
	{
		ID: "go.security.plaintext-http-request", Code: "CS076", Title: "Request Sent over Plaintext HTTP", Category: CategorySecurity, DefaultSeverity: medium,
		CWE: "CWE-319", OWASP: "A04:2025",
		Summary: "http.Get is called with a constant http:// URL of a host other than localhost.",
		Explanation: "Data sent over plain HTTP can be read and changed by anyone on the network path: credentials, tokens, and the response the program acts on. " +
			"The rule matches constant URLs only, so it has no false positives from variables; URLs of localhost, 127.0.0.1 and [::1] are allowed for local services and tests.",
		BadExample:  `resp, err := http.Get("http://api.example.com/v1/rates")`,
		GoodExample: `resp, err := http.Get("https://api.example.com/v1/rates")`,
		References:  []string{cweURL + "319.html"},
	},
	{
		ID: "go.security.plaintext-http-request-new", Code: "CS077", Title: "Request Built for Plaintext HTTP", Category: CategorySecurity, DefaultSeverity: medium,
		CWE: "CWE-319", OWASP: "A04:2025",
		Summary: "http.NewRequestWithContext is called with a constant http:// URL of a host other than localhost.",
		Explanation: "A request built for a plain HTTP URL travels unencrypted, so headers such as Authorization and the body can be read and changed in transit. " +
			"Like go.security.plaintext-http-request, only constant URLs are matched and local hosts are allowed.",
		BadExample:  `req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://billing.example.com/charge", body)`,
		GoodExample: `req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://billing.example.com/charge", body)`,
		References:  []string{cweURL + "319.html"},
	},
	{
		ID: "go.architecture.sql-in-transport-layer", Code: "CS078", Title: "Database Access in Transport Layer", Category: CategoryArchitecture, DefaultSeverity: low,
		Summary: "A package named handler, api, transport, web, http or controller calls methods of *sql.DB or *sql.Tx directly.",
		Explanation: "When handlers run queries themselves, request parsing, authorization and storage logic mix in one place: every handler must repeat the same scoping and error handling, and the queries cannot be tested without HTTP. " +
			"A repository or store package behind an interface keeps the transport layer thin and gives queries one place to be reviewed.",
		BadExample: `func (h *Handler) GetOrder(w http.ResponseWriter, r *http.Request) {
	row := h.db.QueryRowContext(r.Context(), "SELECT id, total FROM orders WHERE id = $1", r.PathValue("id"))
	_ = row
}`,
		GoodExample: `func (h *Handler) GetOrder(w http.ResponseWriter, r *http.Request) {
	order, err := h.orders.Get(r.Context(), r.PathValue("id"))
	_, _ = order, err
}`,
		References: []string{"https://martinfowler.com/eaaCatalog/repository.html"},
	},
	{
		ID: "go.architecture.http-in-data-layer", Code: "CS079", Title: "HTTP Routing in Data Layer", Category: CategoryArchitecture, DefaultSeverity: low,
		Summary: "A package named repository, dao, model, store or storage registers HTTP handlers with http.HandleFunc.",
		Explanation: "Routes registered from the data layer couple storage to the transport, register handlers as a side effect of importing a storage package, and bypass the middleware the transport layer applies. " +
			"Register routes where the server is assembled and let the data layer expose functions.",
		BadExample: `// package repository
func init() {
	http.HandleFunc("/orders", listOrders)
}`,
		GoodExample: `// package api
func Routes(mux *http.ServeMux, h *Handler) {
	mux.HandleFunc("GET /orders", h.ListOrders)
}`,
		References: []string{"https://en.wikipedia.org/wiki/Separation_of_concerns"},
	},
	{
		ID: "go.style.strings-replace-all", Code: "CS080", Title: "Use strings.ReplaceAll", Category: CategoryStyle, DefaultSeverity: info,
		Summary:     "strings.Replace is called with n = -1.",
		Explanation: "strings.ReplaceAll states the intent directly; a -1 count is easy to misread or to change by accident. The fix rewrites the call.",
		BadExample:  `out := strings.Replace(name, " ", "_", -1)`,
		GoodExample: `out := strings.ReplaceAll(name, " ", "_")`,
		References:  []string{"https://pkg.go.dev/strings#ReplaceAll"},
		HasAutoFix:  true,
	},
	{
		ID: "go.style.time-since", Code: "CS081", Title: "Use time.Since", Category: CategoryStyle, DefaultSeverity: info,
		Summary:     "time.Now().Sub(t) computes the elapsed time.",
		Explanation: "time.Since(t) is the idiomatic form of time.Now().Sub(t) and reads as what it measures. The fix rewrites the expression.",
		BadExample:  `elapsed := time.Now().Sub(start)`,
		GoodExample: `elapsed := time.Since(start)`,
		References:  []string{"https://pkg.go.dev/time#Since"},
		HasAutoFix:  true,
	},
	{
		ID: "go.style.bytes-equal", Code: "CS082", Title: "Use bytes.Equal", Category: CategoryStyle, DefaultSeverity: info,
		Summary:     "bytes.Compare(a, b) == 0 tests two byte slices for equality.",
		Explanation: "bytes.Equal says what is tested and does not compute an ordering. For secrets such as tokens or MACs use subtle.ConstantTimeCompare or hmac.Equal instead; see auth-non-constant-time-compare. The fix rewrites the comparison.",
		BadExample:  `same := bytes.Compare(got, want) == 0`,
		GoodExample: `same := bytes.Equal(got, want)`,
		References:  []string{"https://pkg.go.dev/bytes#Equal"},
		HasAutoFix:  true,
	},
	{
		ID: "go.correctness.self-assignment", Code: "CS083", Title: "Self Assignment", Category: CategoryCorrectness, DefaultSeverity: low,
		Summary:     "A variable or field is assigned to itself.",
		Explanation: "x = x has no effect. It usually hides a typo, such as assigning a field to itself instead of copying it from a parameter, which leaves the field at its zero value.",
		BadExample: `func (s *Server) SetTimeout(timeout time.Duration) {
	s.timeout = s.timeout
}`,
		GoodExample: `func (s *Server) SetTimeout(timeout time.Duration) {
	s.timeout = timeout
}`,
	},
}
