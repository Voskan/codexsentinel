package catalog

import "github.com/Voskan/codexsentinel/v2/analyzer/result"

const (
	critical = result.SeverityCritical
	high     = result.SeverityHigh
	medium   = result.SeverityMedium
	low      = result.SeverityLow
)

const cweURL = "https://cwe.mitre.org/data/definitions/"

// securityDocs covers injection, access control and web rules.
var securityDocs = []RuleDoc{
	{
		ID: "sql-injection", Code: "CS001", Title: "SQL Injection", Category: CategorySecurity, DefaultSeverity: high,
		CWE: "CWE-89", OWASP: "A05:2025",
		Summary: "A SQL statement is built from untrusted data.",
		Explanation: "Concatenating or formatting request data into a query lets the client change the statement's structure: read other rows, bypass a WHERE clause or run additional statements. " +
			"database/sql, sqlx, pgx and gorm all accept placeholders whose values the driver sends separately from the SQL text, so the input can never become syntax. " +
			"The taint engine follows the data across functions, closures and struct fields and shows the path.",
		BadExample: `func user(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	row := db.QueryRowContext(r.Context(), "SELECT name FROM users WHERE id = "+id)
	_ = row.Scan(&name)
}`,
		GoodExample: `func user(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	row := db.QueryRowContext(r.Context(), "SELECT name FROM users WHERE id = $1", id)
	_ = row.Scan(&name)
}`,
		References: []string{cweURL + "89.html", "https://go.dev/doc/database/sql-injection"},
	},
	{
		ID: "command-injection", Code: "CS002", Title: "OS Command Injection", Category: CategorySecurity, DefaultSeverity: high,
		CWE: "CWE-78", OWASP: "A05:2025",
		Summary: "A process is started with a command line built from untrusted data.",
		Explanation: "Passing input to sh -c lets shell metacharacters (;, |, $()) run arbitrary commands. Even without a shell, a user-chosen executable or a leading - in an argument changes what runs. " +
			"Run a fixed executable, pass input as separate arguments after --, and validate it against an allowlist.",
		BadExample: `func convert(r *http.Request) error {
	name := r.FormValue("file")
	return exec.Command("sh", "-c", "convert "+name+" out.png").Run()
}`,
		GoodExample: `func convert(r *http.Request) error {
	name := filepath.Base(r.FormValue("file"))
	if !validName.MatchString(name) {
		return errInvalidName
	}
	return exec.CommandContext(r.Context(), "convert", "--", name, "out.png").Run()
}`,
		References: []string{cweURL + "78.html"},
	},
	{
		ID: "path-traversal", Code: "CS003", Title: "Path Traversal", Category: CategorySecurity, DefaultSeverity: high,
		CWE: "CWE-22", OWASP: "A01:2025",
		Summary: "A file path is built from untrusted data without confinement.",
		Explanation: "Names such as ../../etc/passwd or absolute paths escape the intended directory; filepath.Join and filepath.Clean do not prevent that. " +
			"Go 1.24 os.Root confines every operation, including symlink resolution, to one directory, which also closes the race between a check and the open. Access through os.Root is never reported.",
		BadExample: `func download(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, filepath.Join("/srv/files", r.URL.Query().Get("name")))
}`,
		GoodExample: `func download(w http.ResponseWriter, r *http.Request) {
	root, err := os.OpenRoot("/srv/files")
	if err != nil {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	defer root.Close()
	f, err := root.Open(r.URL.Query().Get("name"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	_, _ = io.Copy(w, f)
}`,
		References: []string{cweURL + "22.html", "https://go.dev/blog/osroot"},
	},
	{
		ID: "ssrf", Code: "CS004", Title: "Server-Side Request Forgery", Category: CategorySecurity, DefaultSeverity: medium,
		CWE: "CWE-918", OWASP: "A01:2025",
		Summary: "An outbound request is sent to a URL controlled by the client.",
		Explanation: "The server's network position is trusted by internal services and cloud metadata endpoints (169.254.169.254). A URL from the request lets an attacker reach them through the server. " +
			"Requests whose URL is built from a fixed host are reported with lower severity; a URL taken entirely from input is reported as the taint flow.",
		BadExample: `func preview(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(r.URL.Query().Get("url"))
	if err == nil {
		defer resp.Body.Close()
		_, _ = io.Copy(w, resp.Body)
	}
}`,
		GoodExample: `func preview(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.URL.Query().Get("url"))
	if err != nil || u.Scheme != "https" || !allowedHosts[u.Hostname()] {
		http.Error(w, "host not allowed", http.StatusBadRequest)
		return
	}
	resp, err := client.Get(u.String())
	if err == nil {
		defer resp.Body.Close()
		_, _ = io.Copy(w, resp.Body)
	}
}`,
		References: []string{cweURL + "918.html"},
	},
	{
		ID: "xss", Code: "CS005", Title: "Cross-Site Scripting", Category: CategorySecurity, DefaultSeverity: high,
		CWE: "CWE-79", OWASP: "A05:2025",
		Summary: "Untrusted data is written into an HTML response without escaping.",
		Explanation: "Writing request data to a ResponseWriter, or converting it to template.HTML, lets an attacker inject script that runs with the victim's session. " +
			"html/template escapes values according to their context; text/template and fmt do not.",
		BadExample: `func hello(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<h1>Hello %s</h1>", r.URL.Query().Get("name"))
}`,
		GoodExample: `var page = template.Must(template.New("p").Parse("<h1>Hello {{.}}</h1>"))

func hello(w http.ResponseWriter, r *http.Request) {
	_ = page.Execute(w, r.URL.Query().Get("name"))
}`,
		References: []string{cweURL + "79.html", "https://pkg.go.dev/html/template"},
	},
	{
		ID: "open-redirect", Code: "CS006", Title: "Open Redirect", Category: CategorySecurity, DefaultSeverity: medium,
		CWE: "CWE-601", OWASP: "A01:2025",
		Summary: "A redirect location comes from untrusted data.",
		Explanation: "A link to a trusted site that redirects to an attacker's page makes phishing convincing and can leak OAuth codes or tokens in the URL. " +
			"Accept only relative paths that start with a single slash, or hosts from an allowlist.",
		BadExample: `func login(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
}`,
		GoodExample: `func login(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusFound)
}`,
		References: []string{cweURL + "601.html"},
	},
	{
		ID: "archive-zip-slip", Code: "CS007", Title: "Archive Path Traversal (Zip Slip)", Category: CategorySecurity, DefaultSeverity: critical,
		CWE: "CWE-22", OWASP: "A01:2025",
		Summary: "Archive entry names are used as file paths without confinement.",
		Explanation: "Entry names in zip and tar archives are attacker-controlled and may contain ../ or absolute paths, so extracting writes outside the target directory, for example over a binary or an SSH key. " +
			"Extract through os.Root, or check that the cleaned path stays inside the destination.",
		BadExample: `for _, f := range zr.File {
	out, _ := os.Create(filepath.Join(dest, f.Name))
	rc, _ := f.Open()
	_, _ = io.Copy(out, rc)
}`,
		GoodExample: `root, err := os.OpenRoot(dest)
if err != nil {
	return err
}
defer root.Close()
for _, f := range zr.File {
	out, err := root.Create(f.Name) // fails for names that leave dest
	if err != nil {
		return err
	}
	rc, _ := f.Open()
	_, err = io.Copy(out, io.LimitReader(rc, maxEntrySize))
	rc.Close()
	out.Close()
}`,
		References: []string{cweURL + "22.html", "https://security.snyk.io/research/zip-slip-vulnerability"},
	},
	{
		ID: "archive-decompression-bomb", Code: "CS008", Title: "Unbounded Decompression", Category: CategorySecurity, DefaultSeverity: medium,
		CWE: "CWE-409", OWASP: "A06:2025",
		Summary: "Compressed input is decompressed without a size limit.",
		Explanation: "A few kilobytes of gzip or zip data can expand to gigabytes, exhausting memory or disk. Copying a decompressor with io.Copy or io.ReadAll has no bound. " +
			"Wrap the reader in io.LimitReader and treat hitting the limit as an error.",
		BadExample: `zr, _ := gzip.NewReader(r.Body)
data, _ := io.ReadAll(zr)`,
		GoodExample: `zr, err := gzip.NewReader(http.MaxBytesReader(w, r.Body, 1<<20))
if err != nil {
	return err
}
data, err := io.ReadAll(io.LimitReader(zr, 10<<20))`,
		References: []string{cweURL + "409.html"},
	},
	{
		ID: "idor-unscoped-mutation", Code: "CS009", Title: "Unscoped Resource Mutation (IDOR)", Category: CategorySecurity, DefaultSeverity: medium,
		CWE: "CWE-639", OWASP: "A01:2025",
		Summary: "A record is updated or deleted by an ID from the request without an owner condition.",
		Explanation: "When a handler deletes or updates by an ID from the URL alone, any authenticated user can change other users' records by guessing IDs. " +
			"Scope the statement to the caller: add the owner or tenant from the session to the WHERE clause and check the number of affected rows.",
		BadExample: `func deleteNote(w http.ResponseWriter, r *http.Request) {
	_, _ = db.ExecContext(r.Context(), "DELETE FROM notes WHERE id = $1", r.PathValue("id"))
}`,
		GoodExample: `func deleteNote(w http.ResponseWriter, r *http.Request) {
	userID := session.UserID(r.Context())
	res, err := db.ExecContext(r.Context(), "DELETE FROM notes WHERE id = $1 AND owner_id = $2", r.PathValue("id"), userID)
	if n, _ := res.RowsAffected(); err != nil || n == 0 {
		http.NotFound(w, r)
	}
}`,
		References: []string{cweURL + "639.html"},
	},
	{
		ID: "api-excessive-data-exposure", Code: "CS010", Title: "Sensitive Field Exposed in JSON Response", Category: CategorySecurity, DefaultSeverity: high,
		CWE: "CWE-200", OWASP: "A01:2025",
		Summary: "A JSON response type contains a stored secret, such as a password hash, without json:\"-\".",
		Explanation: "Encoding a storage model straight into a response sends every exported field, including password hashes, salts, private keys or TOTP secrets added later. " +
			"The rule follows the encoded type through pointers, slices, maps and nested structs. Tag the field json:\"-\" or respond with a dedicated response type. Note that json:\"-,\" still encodes the field, under the key \"-\".",
		BadExample:  "type User struct {\n\tID           int64  `json:\"id\"`\n\tEmail        string `json:\"email\"`\n\tPasswordHash string `json:\"password_hash\"`\n}\n\nfunc list(w http.ResponseWriter, r *http.Request) {\n\t_ = json.NewEncoder(w).Encode(users)\n}",
		GoodExample: "type User struct {\n\tID           int64  `json:\"id\"`\n\tEmail        string `json:\"email\"`\n\tPasswordHash string `json:\"-\"`\n}\n\nfunc list(w http.ResponseWriter, r *http.Request) {\n\t_ = json.NewEncoder(w).Encode(users)\n}",
		References:  []string{"https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/", cweURL + "200.html"},
	},
	{
		ID: "api-mass-assignment", Code: "CS011", Title: "Request Body Bound to Database Model", Category: CategorySecurity, DefaultSeverity: high,
		CWE: "CWE-915", OWASP: "A01:2025",
		Summary: "A request body is decoded into a database model that has privileged fields.",
		Explanation: "Decoding JSON into the model you save lets the client set any exported field it names, such as {\"is_admin\": true} or a balance. " +
			"A model is recognized by ORM tags (gorm, db, bun, sql, bson, xorm) or by being saved in the same function. Decode into a request type with only the editable fields and copy them.",
		BadExample: `func update(w http.ResponseWriter, r *http.Request) {
	var u User // has IsAdmin and gorm tags
	_ = json.NewDecoder(r.Body).Decode(&u)
	db.Save(&u)
}`,
		GoodExample: `type UpdateProfileRequest struct {
	Name string ` + "`json:\"name\"`" + `
}

func update(w http.ResponseWriter, r *http.Request) {
	var req UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	u := currentUser(r)
	u.Name = req.Name
	db.Save(u)
}`,
		References: []string{"https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html", cweURL + "915.html"},
	},
	{
		ID: "csrf-missing-protection", Code: "CS012", Title: "Missing CSRF Protection", Category: CategorySecurity, DefaultSeverity: medium,
		CWE: "CWE-352", OWASP: "A01:2025",
		Summary: "A state-changing route with cookie sessions has no cross-origin protection.",
		Explanation: "Browsers attach cookies to requests that other sites trigger, so a form on a malicious page can submit POSTs as the victim. " +
			"Go 1.25 http.CrossOriginProtection rejects cross-origin unsafe requests using Sec-Fetch-Site; gorilla/csrf, nosurf and the framework CSRF middlewares are recognized as well.",
		BadExample: `mux.HandleFunc("POST /transfer", transfer)
http.ListenAndServe(":8080", sessions.Wrap(mux))`,
		GoodExample: `mux.HandleFunc("POST /transfer", transfer)
protect := http.NewCrossOriginProtection()
http.ListenAndServe(":8080", protect.Handler(sessions.Wrap(mux)))`,
		References: []string{cweURL + "352.html", "https://pkg.go.dev/net/http#CrossOriginProtection"},
	},
	{
		ID: "websocket-origin-bypass", Code: "CS013", Title: "WebSocket Origin Check Disabled", Category: CategorySecurity, DefaultSeverity: high,
		CWE: "CWE-346", OWASP: "A01:2025",
		Summary:     "A WebSocket upgrader accepts connections from any origin.",
		Explanation: "WebSocket handshakes carry cookies, and browsers do not apply the same-origin policy to them. A CheckOrigin that returns true lets any website open an authenticated socket as the visitor (cross-site WebSocket hijacking).",
		BadExample: `var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}`,
		GoodExample: `var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return r.Header.Get("Origin") == "https://app.example.com"
	},
}`,
		References: []string{cweURL + "346.html"},
	},
	{
		ID: "ssrf-missing-ip-guard", Code: "CS014", Title: "Outbound HTTP Transport Without IP Restrictions", Category: CategorySecurity, DefaultSeverity: medium,
		CWE: "CWE-918", OWASP: "A01:2025",
		Summary: "A client that fetches dynamic URLs uses a transport without an IP-checking dialer.",
		Explanation: "Validating a URL's host is not enough: DNS can resolve an allowed name to 127.0.0.1 or 169.254.169.254, or change between the check and the request (DNS rebinding). " +
			"Checking the resolved address in net.Dialer.Control closes that gap because it runs for the address actually connected to.",
		BadExample: `client := &http.Client{Transport: &http.Transport{}}
resp, err := client.Get(webhookURL)`,
		GoodExample: `dialer := &net.Dialer{Control: func(network, address string, _ syscall.RawConn) error {
	host, _, _ := net.SplitHostPort(address)
	if ip := net.ParseIP(host); ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return errors.New("destination not allowed")
	}
	return nil
}}
client := &http.Client{Transport: &http.Transport{DialContext: dialer.DialContext}}`,
		References: []string{cweURL + "918.html"},
	},
	{
		ID: "cors-wildcard-credentials", Code: "CS015", Title: "CORS Allows Credentials From Any Origin", Category: CategorySecurity, DefaultSeverity: high,
		CWE: "CWE-942", OWASP: "A02:2025",
		Summary:     "CORS reflects any origin while allowing credentials.",
		Explanation: "Allowing credentials together with a wildcard or a reflected Origin lets any website read authenticated responses from the API in the visitor's browser.",
		BadExample: `w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
w.Header().Set("Access-Control-Allow-Credentials", "true")`,
		GoodExample: `if origin := r.Header.Get("Origin"); allowedOrigins[origin] {
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Add("Vary", "Origin")
}`,
		References: []string{cweURL + "942.html"},
	},
	{
		ID: "debug-endpoint-exposed", Code: "CS016", Title: "Debug Endpoint Exposed", Category: CategorySecurity, DefaultSeverity: medium,
		CWE: "CWE-489", OWASP: "A02:2025",
		Summary:     "pprof or expvar handlers are served on the public listener.",
		Explanation: "Importing net/http/pprof registers profiling handlers on http.DefaultServeMux. On a public server they disclose memory contents, goroutine stacks and command-line flags and allow expensive profiling requests.",
		BadExample: `import _ "net/http/pprof"

func main() { http.ListenAndServe(":8080", nil) }`,
		GoodExample: `func main() {
	go func() { _ = http.ListenAndServe("127.0.0.1:6060", nil) }() // pprof on loopback only
	_ = http.ListenAndServe(":8080", appMux)
}`,
		References: []string{cweURL + "489.html"},
	},
	{
		ID: "graphql-introspection-enabled", Code: "CS017", Title: "GraphQL Introspection Enabled Unconditionally", Category: CategorySecurity, DefaultSeverity: low,
		CWE: "CWE-200", OWASP: "A02:2025",
		Summary:     "GraphQL introspection is enabled in every environment.",
		Explanation: "Introspection publishes the full schema, including internal and admin-only fields, which helps attackers find unprotected operations. Enable it only in development.",
		BadExample: `srv := handler.New(es)
srv.Use(extension.Introspection{})`,
		GoodExample: `srv := handler.New(es)
if cfg.Environment == "development" {
	srv.Use(extension.Introspection{})
}`,
		References: []string{cweURL + "200.html"},
	},
	{
		ID: "http-server-missing-timeout", Code: "CS018", Title: "HTTP Server Without Read Timeouts", Category: CategorySecurity, DefaultSeverity: high,
		CWE: "CWE-400", OWASP: "A02:2025",
		Summary:     "An HTTP server is started without ReadHeaderTimeout or ReadTimeout.",
		Explanation: "http.ListenAndServe and a Server without read timeouts keep connections open for clients that send headers byte by byte (Slowloris), so a few hosts can exhaust file descriptors and goroutines.",
		BadExample:  `http.ListenAndServe(":8080", mux)`,
		GoodExample: `srv := &http.Server{
	Addr:              ":8080",
	Handler:           mux,
	ReadHeaderTimeout: 5 * time.Second,
	ReadTimeout:       30 * time.Second,
	IdleTimeout:       2 * time.Minute,
}
_ = srv.ListenAndServe()`,
		References: []string{cweURL + "400.html"},
	},
	{
		ID: "insecure-file-permissions", Code: "CS019", Title: "Insecure File Permissions", Category: CategorySecurity, DefaultSeverity: medium,
		CWE: "CWE-732", OWASP: "A02:2025",
		Summary:     "A file or directory is created world-writable or a secret file world-readable.",
		Explanation: "Modes such as 0777 or 0666 let every local user modify the file, and 0644 on keys or tokens lets them read it. Use 0600 for secrets and 0750 or 0755 for directories.",
		BadExample:  `os.WriteFile("token", tok, 0o666)`,
		GoodExample: `os.WriteFile("token", tok, 0o600)`,
		References:  []string{cweURL + "732.html"},
	},
	{
		ID: "crypto-weak-hash", Code: "CS020", Title: "Weak Hash Algorithm", Category: CategorySecurity, DefaultSeverity: medium,
		CWE: "CWE-328", OWASP: "A04:2025",
		Summary:     "MD5 or SHA-1 is used for a security purpose, or a fast hash stores passwords.",
		Explanation: "MD5 and SHA-1 have practical collisions, and any fast hash lets attackers test billions of password guesses per second. Use SHA-256 or SHA-3 for integrity and bcrypt, scrypt or Argon2id for passwords.",
		BadExample:  `sum := md5.Sum([]byte(password))`,
		GoodExample: `hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)`,
		References:  []string{cweURL + "328.html"},
	},
	{
		ID: "crypto-weak-cipher", Code: "CS021", Title: "Weak Cipher or Static Nonce", Category: CategorySecurity, DefaultSeverity: high,
		CWE: "CWE-327", OWASP: "A04:2025",
		Summary:     "DES, RC4, ECB mode or a constant nonce or IV is used.",
		Explanation: "DES and RC4 are broken, ECB leaks patterns of the plaintext, and reusing a nonce with GCM reveals the XOR of plaintexts and allows forgeries. Use AES-GCM or ChaCha20-Poly1305 with a random nonce per message.",
		BadExample: `nonce := make([]byte, 12) // all zero, reused for every message
ct := aead.Seal(nil, nonce, plaintext, nil)`,
		GoodExample: `nonce := make([]byte, aead.NonceSize())
if _, err := rand.Read(nonce); err != nil {
	return err
}
ct := aead.Seal(nonce, nonce, plaintext, nil)`,
		References: []string{cweURL + "327.html"},
	},
	{
		ID: "crypto-weak-rand", Code: "CS022", Title: "Insecure Randomness for Security Value", Category: CategorySecurity, DefaultSeverity: high,
		CWE: "CWE-338", OWASP: "A04:2025",
		Summary:     "math/rand generates a token, key, password or nonce.",
		Explanation: "math/rand and math/rand/v2 generators are not cryptographically secure; their output can be predicted from earlier values. Use crypto/rand, for example rand.Text for tokens (Go 1.24).",
		BadExample:  `token := fmt.Sprintf("%x", mathrand.Int63())`,
		GoodExample: `token := rand.Text() // crypto/rand, Go 1.24`,
		References:  []string{cweURL + "338.html"},
	},
	{
		ID: "crypto-weak-rsa", Code: "CS023", Title: "Weak RSA Key Size", Category: CategorySecurity, DefaultSeverity: high,
		CWE: "CWE-326", OWASP: "A04:2025",
		Summary:     "An RSA key shorter than 2048 bits is generated.",
		Explanation: "Keys below 2048 bits can be factored with practical resources. Go 1.24 refuses keys under 1024 bits by default; use 2048 bits or more, or switch to Ed25519 or ECDSA P-256.",
		BadExample:  `key, err := rsa.GenerateKey(rand.Reader, 1024)`,
		GoodExample: `key, err := rsa.GenerateKey(rand.Reader, 3072)`,
		References:  []string{cweURL + "326.html"},
	},
	{
		ID: "tls-insecure-config", Code: "CS024", Title: "Insecure TLS Configuration", Category: CategorySecurity, DefaultSeverity: high,
		CWE: "CWE-295", OWASP: "A04:2025", HasAutoFix: true,
		Summary:     "TLS certificate verification is disabled or versions older than TLS 1.2 are allowed.",
		Explanation: "InsecureSkipVerify accepts any certificate, so anyone on the network path can impersonate the server. TLS 1.0 and 1.1 have known weaknesses. --fix sets InsecureSkipVerify to false and MinVersion to tls.VersionTLS12.",
		BadExample:  `cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}`,
		GoodExample: `cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}`,
		References:  []string{cweURL + "295.html"},
	},
	{
		ID: "grpc-insecure-credentials", Code: "CS025", Title: "gRPC Connection Without Transport Security", Category: CategorySecurity, DefaultSeverity: high,
		CWE: "CWE-319", OWASP: "A04:2025",
		Summary:     "A gRPC client dials a remote target with insecure credentials.",
		Explanation: "insecure.NewCredentials() and grpc.WithInsecure() send requests, metadata and tokens in clear text. Loopback, bufnet and Unix socket targets are not reported.",
		BadExample:  `conn, err := grpc.NewClient("payments.internal:443", grpc.WithTransportCredentials(insecure.NewCredentials()))`,
		GoodExample: `creds := credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
conn, err := grpc.NewClient("payments.internal:443", grpc.WithTransportCredentials(creds))`,
		References: []string{cweURL + "319.html", "https://grpc.io/docs/guides/auth/"},
	},
	{
		ID: "jwt-alg-none", Code: "CS026", Title: "JWT 'none' Algorithm Allowed", Category: CategorySecurity, DefaultSeverity: critical,
		CWE: "CWE-347", OWASP: "A04:2025",
		Summary:     "Unsigned JWTs are accepted or created.",
		Explanation: "With the none algorithm a token carries no signature, so anyone can forge claims such as the user ID or role.",
		BadExample:  `token, err := jwt.Parse(raw, keyFunc, jwt.WithValidMethods([]string{"none", "HS256"}))`,
		GoodExample: `token, err := jwt.Parse(raw, keyFunc, jwt.WithValidMethods([]string{"HS256"}))`,
		References:  []string{cweURL + "347.html"},
	},
	{
		ID: "jwt-unverified-parse", Code: "CS027", Title: "JWT Parsed Without Signature Verification", Category: CategorySecurity, DefaultSeverity: high,
		CWE: "CWE-347", OWASP: "A07:2025",
		Summary:     "Claims are read from a token parsed without verifying its signature.",
		Explanation: "ParseUnverified decodes any token, so trusting its claims for authentication accepts forged tokens.",
		BadExample: `token, _, err := jwt.NewParser().ParseUnverified(raw, &claims)
userID := claims.Subject`,
		GoodExample: `token, err := jwt.ParseWithClaims(raw, &claims, keyFunc, jwt.WithValidMethods([]string{"RS256"}))
if err != nil || !token.Valid {
	return errUnauthorized
}`,
		References: []string{cweURL + "347.html"},
	},
	{
		ID: "jwt-missing-alg-check", Code: "CS028", Title: "JWT Signing Algorithm Not Enforced", Category: CategorySecurity, DefaultSeverity: high,
		CWE: "CWE-347", OWASP: "A07:2025",
		Summary:     "A JWT is verified without restricting the signing algorithm.",
		Explanation: "If the key function does not check the algorithm, a token signed with HS256 using the public RSA key as HMAC secret can pass verification (algorithm confusion).",
		BadExample:  `token, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) { return publicKey, nil })`,
		GoodExample: `token, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) { return publicKey, nil },
	jwt.WithValidMethods([]string{"RS256"}))`,
		References: []string{cweURL + "347.html"},
	},
	{
		ID: "jwt-weak-secret", Code: "CS029", Title: "Hardcoded or Weak JWT Signing Secret", Category: CategorySecurity, DefaultSeverity: high,
		CWE: "CWE-326", OWASP: "A04:2025",
		Summary:     "A JWT is signed with a constant or short secret.",
		Explanation: "A secret in the source is visible to everyone with repository access, and short HMAC secrets can be brute-forced offline from a single token. Load at least 32 random bytes from a secret store.",
		BadExample:  `signed, err := token.SignedString([]byte("secret"))`,
		GoodExample: `signed, err := token.SignedString(signingKey) // 32+ random bytes from the secret store`,
		References:  []string{cweURL + "326.html"},
	},
	{
		ID: "auth-hardcoded-credential", Code: "CS030", Title: "Hardcoded Credential Check", Category: CategorySecurity, DefaultSeverity: critical,
		CWE: "CWE-798", OWASP: "A07:2025",
		Summary:     "A password or token is compared with a constant in the code.",
		Explanation: "A credential in the source cannot be rotated and is known to everyone who can read the code or the binary; it often acts as a backdoor.",
		BadExample: `if r.Header.Get("X-Admin-Token") == "letmein" {
	grantAdmin(r)
}`,
		GoodExample: `if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Admin-Token")), adminToken) == 1 {
	grantAdmin(r)
}`,
		References: []string{cweURL + "798.html"},
	},
	{
		ID: "auth-non-constant-time-compare", Code: "CS031", Title: "Secret Compared in Non-Constant Time", Category: CategorySecurity, DefaultSeverity: high,
		CWE: "CWE-208", OWASP: "A07:2025",
		Summary:     "A secret such as a token, MAC or password hash is compared with == or bytes.Equal.",
		Explanation: "These comparisons stop at the first differing byte, so response timing reveals how much of a guess is correct. Use crypto/subtle.ConstantTimeCompare or hmac.Equal.",
		BadExample: `if r.Header.Get("X-Signature") == expectedSignature {
	process(r)
}`,
		GoodExample: `if hmac.Equal([]byte(r.Header.Get("X-Signature")), []byte(expectedSignature)) {
	process(r)
}`,
		References: []string{cweURL + "208.html"},
	},
	{
		ID: "hardcoded-secret", Code: "CS032", Title: "Hardcoded Secret", Category: CategorySecurity, DefaultSeverity: high,
		CWE: "CWE-798", OWASP: "A07:2025",
		Summary:     "An API key, private key or similar credential is embedded in the source.",
		Explanation: "Provider-specific patterns and an entropy check find credentials such as cloud keys and tokens. Anything committed to a repository should be considered leaked: rotate it and load it from the environment or a secret manager.",
		BadExample:  `const stripeKey = "sk_live_51H..."`,
		GoodExample: `stripeKey := os.Getenv("STRIPE_API_KEY")`,
		References:  []string{cweURL + "798.html"},
	},
	{
		ID: "cookie-missing-httponly", Code: "CS033", Title: "Session Cookie Without HttpOnly", Category: CategorySecurity, DefaultSeverity: medium,
		CWE: "CWE-1004", OWASP: "A07:2025",
		Summary:     "A session cookie is readable by JavaScript.",
		Explanation: "Without HttpOnly, any XSS on the site can read the session cookie and send it to an attacker.",
		BadExample:  `http.SetCookie(w, &http.Cookie{Name: "session", Value: id, Secure: true})`,
		GoodExample: `http.SetCookie(w, &http.Cookie{Name: "session", Value: id, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})`,
		References:  []string{cweURL + "1004.html"},
	},
	{
		ID: "cookie-missing-secure", Code: "CS034", Title: "Session Cookie Without Secure", Category: CategorySecurity, DefaultSeverity: medium,
		CWE: "CWE-614", OWASP: "A07:2025",
		Summary:     "A session cookie may be sent over plain HTTP.",
		Explanation: "Without Secure, the browser also sends the cookie over http:// requests, where anyone on the network can read it.",
		BadExample:  `http.SetCookie(w, &http.Cookie{Name: "session", Value: id, HttpOnly: true})`,
		GoodExample: `http.SetCookie(w, &http.Cookie{Name: "session", Value: id, HttpOnly: true, Secure: true})`,
		References:  []string{cweURL + "614.html"},
	},
	{
		ID: "cookie-insecure-samesite", Code: "CS035", Title: "Insecure Cookie SameSite Policy", Category: CategorySecurity, DefaultSeverity: medium,
		CWE: "CWE-1275", OWASP: "A07:2025",
		Summary:     "A session cookie uses SameSite=None.",
		Explanation: "SameSite=None sends the cookie with cross-site requests, which re-enables CSRF and cross-site leaks. Use Lax or Strict unless the cookie must work in third-party contexts.",
		BadExample:  `http.SetCookie(w, &http.Cookie{Name: "session", Value: id, Secure: true, HttpOnly: true, SameSite: http.SameSiteNoneMode})`,
		GoodExample: `http.SetCookie(w, &http.Cookie{Name: "session", Value: id, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})`,
		References:  []string{cweURL + "1275.html"},
	},
}
