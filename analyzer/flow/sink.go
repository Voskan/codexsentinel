package flow

func sinkSpec(pkg, recv, fn, category, desc string, args ...int) SinkSpec {
	return SinkSpec{Package: pkg, Receiver: recv, Function: fn, CheckArgs: args, WriterArg: -1, Category: category, Description: desc}
}

// builtinSinks lists security-sensitive calls. Argument indexes never count the receiver.
func builtinSinks() []SinkSpec {
	var out []SinkSpec
	for _, group := range [][]SinkSpec{sqlSinks(), commandSinks(), pathSinks(), ssrfSinks(), xssSinks()} {
		out = append(out, group...)
	}
	return append(out, sinkSpec("net/http", "", "Redirect", "open-redirect", "an HTTP redirect location", 2))
}

const sqlDesc = "a SQL query"

func sqlSinks() []SinkSpec {
	var out []SinkSpec
	for _, recv := range []string{"DB", "Tx", "Conn"} {
		for _, m := range []string{"Query", "QueryRow", "Exec", "Prepare"} {
			out = append(out,
				sinkSpec("database/sql", recv, m, "sql-injection", sqlDesc, 0),
				sinkSpec("database/sql", recv, m+"Context", "sql-injection", sqlDesc, 1))
		}
	}
	for _, recv := range []string{"DB", "Tx"} {
		for _, m := range []string{"Queryx", "QueryRowx", "MustExec", "NamedExec", "NamedQuery", "Preparex", "PrepareNamed", "Rebind"} {
			out = append(out, sinkSpec("github.com/jmoiron/sqlx", recv, m, "sql-injection", sqlDesc, 0))
		}
		for _, m := range []string{"QueryxContext", "QueryRowxContext", "MustExecContext", "NamedExecContext", "PreparexContext", "PrepareNamedContext"} {
			out = append(out, sinkSpec("github.com/jmoiron/sqlx", recv, m, "sql-injection", sqlDesc, 1))
		}
		out = append(out,
			sinkSpec("github.com/jmoiron/sqlx", recv, "Get", "sql-injection", sqlDesc, 1),
			sinkSpec("github.com/jmoiron/sqlx", recv, "Select", "sql-injection", sqlDesc, 1),
			sinkSpec("github.com/jmoiron/sqlx", recv, "GetContext", "sql-injection", sqlDesc, 2),
			sinkSpec("github.com/jmoiron/sqlx", recv, "SelectContext", "sql-injection", sqlDesc, 2))
	}
	for _, target := range [][2]string{{"github.com/jackc/pgx/v5", "Conn"}, {"github.com/jackc/pgx/v5", "Tx"}, {"github.com/jackc/pgx/v5/pgxpool", "Pool"}, {"github.com/jackc/pgx/v5/pgxpool", "Conn"}, {"github.com/jackc/pgx/v5/pgxpool", "Tx"}, {"github.com/jackc/pgx/v4", "Conn"}, {"github.com/jackc/pgx/v4", "Tx"}} {
		for _, m := range []string{"Query", "QueryRow", "Exec"} {
			out = append(out, sinkSpec(target[0], target[1], m, "sql-injection", sqlDesc, 1))
		}
	}
	for _, m := range []string{"Raw", "Exec", "Where", "Or", "Not", "Order", "Having", "Group", "Joins", "Select", "Distinct", "Pluck"} {
		out = append(out, sinkSpec("gorm.io/gorm", "DB", m, "sql-injection", sqlDesc, 0))
	}
	return out
}

func commandSinks() []SinkSpec {
	const cmdDesc = "an operating system command"
	return []SinkSpec{
		SinkSpec{Package: "os/exec", Function: "Command", CheckArgs: []int{0, 1}, ShellArgs: true, WriterArg: -1, Category: "command-injection", Description: cmdDesc},
		SinkSpec{Package: "os/exec", Function: "CommandContext", CheckArgs: []int{1, 2}, ShellArgs: true, WriterArg: -1, Category: "command-injection", Description: cmdDesc},
		sinkSpec("syscall", "", "Exec", "command-injection", cmdDesc, 0, 1),
		sinkSpec("syscall", "", "ForkExec", "command-injection", cmdDesc, 0, 1),
		sinkSpec("os", "", "StartProcess", "command-injection", cmdDesc, 0, 1),
	}
}

func pathSinks() []SinkSpec {
	const fsDesc = "a filesystem path"
	var out []SinkSpec
	for _, fn := range []string{"Open", "OpenFile", "ReadFile", "WriteFile", "Create", "Remove", "RemoveAll", "ReadDir", "Mkdir", "MkdirAll", "Truncate", "Chmod", "Chown", "Lstat", "Readlink"} {
		out = append(out, sinkSpec("os", "", fn, "path-traversal", fsDesc, 0))
	}
	for _, fn := range []string{"Rename", "Symlink", "Link"} {
		out = append(out, sinkSpec("os", "", fn, "path-traversal", fsDesc, 0, 1))
	}
	for _, fn := range []string{"ReadFile", "WriteFile", "ReadDir"} {
		out = append(out, sinkSpec("io/ioutil", "", fn, "path-traversal", fsDesc, 0))
	}
	return append(out,
		sinkSpec("net/http", "", "ServeFile", "path-traversal", fsDesc, 2),
		SinkSpec{Package: "net/http", Function: "Dir", Conversion: true, WriterArg: -1, Category: "path-traversal", Description: "an http.Dir file server root"},
	)
}

func ssrfSinks() []SinkSpec {
	const netDesc = "an outbound HTTP request URL"
	return []SinkSpec{
		sinkSpec("net/http", "", "Get", "ssrf", netDesc, 0),
		sinkSpec("net/http", "", "Head", "ssrf", netDesc, 0),
		sinkSpec("net/http", "", "Post", "ssrf", netDesc, 0),
		sinkSpec("net/http", "", "PostForm", "ssrf", netDesc, 0),
		sinkSpec("net/http", "", "NewRequest", "ssrf", netDesc, 1),
		sinkSpec("net/http", "", "NewRequestWithContext", "ssrf", netDesc, 2),
		sinkSpec("net/http", "Client", "Get", "ssrf", netDesc, 0),
		sinkSpec("net/http", "Client", "Head", "ssrf", netDesc, 0),
		sinkSpec("net/http", "Client", "Post", "ssrf", netDesc, 0),
		sinkSpec("net/http", "Client", "PostForm", "ssrf", netDesc, 0),
		sinkSpec("net", "", "Dial", "ssrf", "a network address", 1),
		sinkSpec("net", "", "DialTimeout", "ssrf", "a network address", 1),
	}
}

func xssSinks() []SinkSpec {
	var out []SinkSpec
	const xssDesc = "an HTTP response"
	writer := func(pkg, fn string, writerArg int, args ...int) SinkSpec {
		s := sinkSpec(pkg, "", fn, "xss", xssDesc, args...)
		s.WriterArg = writerArg
		return s
	}
	out = append(out,
		sinkSpec("net/http", "ResponseWriter", "Write", "xss", xssDesc, 0),
		writer("io", "WriteString", 0, 1),
		writer("fmt", "Fprint", 0, 1),
		writer("fmt", "Fprintln", 0, 1),
		writer("fmt", "Fprintf", 0, 1, 2),
	)
	tpl := func(fn string, args ...int) SinkSpec {
		s := sinkSpec("text/template", "Template", fn, "xss", "an unescaped text/template rendered to an HTTP response", args...)
		s.WriterArg = 0
		return s
	}
	out = append(out, tpl("Execute", 1), tpl("ExecuteTemplate", 2))
	for _, typ := range []string{"HTML", "HTMLAttr", "JS", "JSStr", "CSS", "URL", "Srcset"} {
		out = append(out, SinkSpec{Package: "html/template", Function: typ, Conversion: true, WriterArg: -1, Category: "xss", Description: "a trusted html/template." + typ + " value"})
	}
	return out
}
