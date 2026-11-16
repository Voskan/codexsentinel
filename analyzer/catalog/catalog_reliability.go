package catalog

// reliabilityDocs covers resources and goroutines that are not released.
var reliabilityDocs = []RuleDoc{
	{
		ID: "tx-network-io", Code: "CS046", Title: "Blocking Call Inside a Database Transaction", Category: CategoryReliability, DefaultSeverity: high,
		CWE: "CWE-400", OWASP: "A06:2025",
		Summary: "An HTTP, gRPC or network call, or a sleep, happens while a transaction is open.",
		Explanation: "A transaction holds a pooled connection and row locks until it ends. Calling a slow external service inside it keeps both for the duration of that call, so a degraded dependency exhausts the pool and blocks other writers. " +
			"The analysis follows calls through up to eight project functions, including interface calls resolved by the call graph, and reports the chain. Calls started with go are not part of the transaction.",
		BadExample: `tx, err := db.BeginTx(ctx, nil)
if err != nil {
	return err
}
defer tx.Rollback()
if _, err := tx.ExecContext(ctx, "UPDATE orders SET status = 'paid' WHERE id = $1", id); err != nil {
	return err
}
if err := payments.Charge(ctx, id); err != nil { // HTTP call while the row is locked
	return err
}
return tx.Commit()`,
		GoodExample: `if err := payments.Charge(ctx, id); err != nil {
	return err
}
tx, err := db.BeginTx(ctx, nil)
if err != nil {
	return err
}
defer tx.Rollback()
if _, err := tx.ExecContext(ctx, "UPDATE orders SET status = 'paid' WHERE id = $1", id); err != nil {
	return err
}
return tx.Commit()`,
		References: []string{cweURL + "400.html"},
	},
	{
		ID: "lock-blocking-io", Code: "CS047", Title: "Blocking Call While Holding a Mutex", Category: CategoryReliability, DefaultSeverity: medium,
		CWE: "CWE-833", OWASP: "A06:2025",
		Summary:     "A sync.Mutex or RWMutex is held across a network call or sleep.",
		Explanation: "Every goroutine that needs the lock waits for the slowest remote call made under it; with a deferred Unlock the lock is held until the function returns. Copy what you need, unlock, then do the I/O.",
		BadExample: `c.mu.Lock()
defer c.mu.Unlock()
resp, err := c.client.Get(c.url) // other goroutines wait for the network
`,
		GoodExample: `c.mu.Lock()
url := c.url
c.mu.Unlock()
resp, err := c.client.Get(url)`,
		References: []string{cweURL + "833.html"},
	},
	{
		ID: "sql-tx-missing-rollback", Code: "CS048", Title: "Transaction Not Rolled Back on Early Return", Category: CategoryReliability, DefaultSeverity: high,
		CWE: "CWE-404", OWASP: "A06:2025",
		Summary:     "A return path leaves a transaction neither committed nor rolled back.",
		Explanation: "An abandoned transaction keeps its connection and locks until the database times it out. A deferred Rollback right after Begin covers every path, and calling it after a successful Commit does nothing. Transactions returned or passed to other functions are not reported.",
		BadExample: `tx, err := db.BeginTx(ctx, nil)
if err != nil {
	return err
}
if _, err := tx.ExecContext(ctx, q); err != nil {
	return err // transaction left open
}
return tx.Commit()`,
		GoodExample: `tx, err := db.BeginTx(ctx, nil)
if err != nil {
	return err
}
defer tx.Rollback()
if _, err := tx.ExecContext(ctx, q); err != nil {
	return err
}
return tx.Commit()`,
		References: []string{"https://go.dev/doc/database/execute-transactions"},
	},
	{
		ID: "http-body-unclosed", Code: "CS049", Title: "HTTP Response Body Not Closed", Category: CategoryReliability, DefaultSeverity: high,
		CWE: "CWE-404", OWASP: "A06:2025",
		Summary:     "A response body is never closed.",
		Explanation: "Until the body is closed, the connection cannot return to the pool, so each request leaks a connection and a goroutine. Reading the body with io.ReadAll does not close it. Responses returned or handed to other functions are not reported.",
		BadExample: `resp, err := client.Do(req)
if err != nil {
	return nil, err
}
return io.ReadAll(resp.Body)`,
		GoodExample: `resp, err := client.Do(req)
if err != nil {
	return nil, err
}
defer resp.Body.Close()
return io.ReadAll(resp.Body)`,
		References: []string{"https://pkg.go.dev/net/http#Client.Do"},
	},
	{
		ID: "sql-rows-unclosed", Code: "CS050", Title: "Query Rows Not Closed", Category: CategoryReliability, DefaultSeverity: high,
		CWE: "CWE-404", OWASP: "A06:2025",
		Summary:     "Rows from Query are never closed.",
		Explanation: "Rows hold a connection until they are closed or fully iterated. An early return or a panic inside the loop leaks the connection; defer rows.Close() covers both.",
		BadExample: `rows, err := db.QueryContext(ctx, "SELECT name FROM users")
if err != nil {
	return nil, err
}
for rows.Next() {
	if err := rows.Scan(&name); err != nil {
		return nil, err // connection leaked
	}
}`,
		GoodExample: `rows, err := db.QueryContext(ctx, "SELECT name FROM users")
if err != nil {
	return nil, err
}
defer rows.Close()
for rows.Next() {
	if err := rows.Scan(&name); err != nil {
		return nil, err
	}
}
return names, rows.Err()`,
		References: []string{"https://go.dev/doc/database/querying#multiple_rows"},
	},
	{
		ID: "defer-in-loop", Code: "CS051", Title: "Defer Inside a Loop", Category: CategoryReliability, DefaultSeverity: medium,
		CWE: "CWE-400", OWASP: "A06:2025",
		Summary:     "defer is used in a loop body of the same function.",
		Explanation: "Deferred calls run when the function returns, not at the end of the iteration, so files, locks or rows acquired in each iteration stay open until the loop finishes. Move the body into a function literal or helper.",
		BadExample: `for _, p := range paths {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	process(f)
}`,
		GoodExample: `for _, p := range paths {
	if err := func() error {
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		return process(f)
	}(); err != nil {
		return err
	}
}`,
		References: []string{"https://go.dev/ref/spec#Defer_statements"},
	},
	{
		ID: "goroutine-channel-leak", Code: "CS052", Title: "Goroutine Blocked on Unbuffered Channel", Category: CategoryReliability, DefaultSeverity: medium,
		CWE: "CWE-400", OWASP: "A06:2025",
		Summary:     "A goroutine sends on an unbuffered channel that its caller may stop reading.",
		Explanation: "When the caller returns on ctx.Done() or an early error, nobody receives the result, and the goroutine blocks forever on its send. Every timed-out request then leaks a goroutine. A buffer of one, or a select on ctx.Done() around the send, lets the goroutine finish.",
		BadExample: `done := make(chan error)
go func() { done <- work() }()
select {
case err := <-done:
	return err
case <-ctx.Done():
	return ctx.Err()
}`,
		GoodExample: `done := make(chan error, 1)
go func() { done <- work() }()
select {
case err := <-done:
	return err
case <-ctx.Done():
	return ctx.Err()
}`,
		References: []string{"https://go.dev/blog/pipelines"},
	},
}
