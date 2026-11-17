# Benchmarks

The benchmark corpora in [`benchmarks/corpus`](../benchmarks/corpus) measure
what the analyzer finds, what it wrongly reports, and how long it takes. Both
are small, self-contained modules that use only the standard library, so the
results can be reproduced offline in seconds.

- **vulnerable-app**: an order service in four layers (`cmd/api`,
  `internal/handler`, `internal/service`, `internal/repo`) with 14 known
  defects in 12 classes, listed with their exact lines in
  [`manifest.json`](../benchmarks/corpus/vulnerable-app/manifest.json).
  Several defects cross package boundaries: the SQL injection starts in the
  handler and reaches `QueryContext` in the repository, and the payment
  request inside the transaction is made by a method that the transaction
  code calls.
- **safe-app**: the same service written safely with current Go: a
  parameterized query and an allowlist for `ORDER BY`, `os.OpenRoot` for user
  file names and archive extraction, `http.NewCrossOriginProtection`, a
  `slog.LogValuer` that redacts the password, request DTOs separate from
  stored models, the payment call before `BeginTx` with a deferred
  `Rollback`, closed response bodies, `subtle.ConstantTimeCompare` and server
  timeouts. No finding is expected. It requires Go 1.25.

## Detection quality

`go test ./benchmarks/` compares the findings with the manifest. It fails when
a defect is missed (recall below 95%), when vulnerable-app produces a finding
that is not in the manifest, or when safe-app produces any finding.

| Corpus | Expected | Found | Missed | Unexpected findings |
| --- | ---: | ---: | ---: | ---: |
| vulnerable-app (defects) | 14 | 14 | 0 | 0 |
| vulnerable-app (additional) | 2 | 2 | 0 | |
| safe-app | 0 | 0 | | 0 |

Recall is 100% and precision 100% on these corpora. The two additional
findings are real consequences of the same code: the downloaded file's
content, chosen by the client, is written to the response (`xss`), and
`http.Get` ignores the context the function receives
(`context-propagation-missing`).

### Comparison

`benchmarks/run_comparison.sh` runs the same corpora through gosec (standalone,
or through golangci-lint when only that is installed) and govulncheck when
they are on `PATH`. Results with golangci-lint 2.15.0 (gosec) and
govulncheck, mapped by hand to the manifest:

| | codex-cli | gosec |
| --- | ---: | ---: |
| vulnerable-app defects found (of 14) | 14 | 6 |
| vulnerable-app findings outside the manifest | 0 | 1 |
| safe-app findings (all false positives) | 0 | 1 |

gosec finds the SQL concatenation, the path traversal, the request to a
variable URL, the missing `ReadHeaderTimeout`, `InsecureSkipVerify` and,
as a generic "file inclusion via variable", the Zip Slip path. It has no
rules for the other classes: secrets in logs, password hashes in JSON
responses, mass assignment, network calls inside transactions, missing
rollbacks, unclosed response bodies, `defer` in loops and non-constant-time
token comparison. Its additional findings are `os.Open` on a path from the
caller, in both corpora.

govulncheck checks dependencies and the standard library for known
vulnerabilities rather than the code itself. On both corpora it reported one
standard library advisory for the local toolchain (Go 1.27.3); upgrading Go
fixes it. It complements a code scanner rather than competing with one.

## Speed

Measured on an Apple M5 Max (18 cores), Go 1.27.3:

| Tool | Corpus | Time (s) | Peak memory (MiB) |
| --- | --- | ---: | ---: |
| codex-cli | vulnerable-app | 1.45 | 938 |
| codex-cli | safe-app | 1.01 | 837 |
| gosec (golangci-lint) | vulnerable-app | 0.44 | 103 |
| gosec (golangci-lint) | safe-app | 0.24 | 106 |
| govulncheck | vulnerable-app | 2.39 | 762 |
| govulncheck | safe-app | 1.88 | 824 |

`go test -run '^$' -bench=BenchmarkFullEngineScan -benchmem ./benchmarks/`:

| Benchmark | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| `BenchmarkFullEngineScan/cold` | 1,003,075,542 | 1,468,990,448 | 22,052,523 |
| `BenchmarkFullEngineScan/warm-cache` | 1,020,802,458 | 1,465,230,184 | 21,971,940 |

codex-cli is slower and uses more memory than gosec because it loads the
whole program with type information and builds SSA and a call graph for the
interprocedural analyses; most of the time and memory go to that step and to
the analysis of the standard library code the program reaches. The analysis
cache stores per-package rule results, and on this five-package corpus all of
them hit on the second run, but whole-program analyses still run, so a warm
cache saves little here. It pays off on larger modules where per-package rules
dominate.

## Reproducing

```bash
go test -v ./benchmarks/
go test -run '^$' -bench=BenchmarkFullEngineScan -benchmem ./benchmarks/
benchmarks/run_comparison.sh
```

The corpora are separate modules, so they are not part of `go test ./...` of
the repository's own packages, and the repository's self-scan excludes them.
