// Command docgen writes the rule reference generated from the rule catalog.
//
//	go run ./cmd/docgen -out docs/rules
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Voskan/codexsentinel/internal/docgen"
)

func main() {
	out := flag.String("out", "docs/rules", "Directory to write the rule reference to")
	flag.Parse()
	if err := docgen.Write(*out); err != nil {
		fmt.Fprintln(os.Stderr, "docgen:", err)
		os.Exit(1)
	}
}
