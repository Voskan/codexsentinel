package main

import (
	"context"

	"github.com/Voskan/codexsentinel/v2/cmd/codex"
)

func main() {
	ctx := context.Background()
	codex.Execute(ctx)
}
