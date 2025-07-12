package main

import (
	"context"

	"github.com/Voskan/codexsentinel/cmd/codex"
)

func main() {
	ctx := context.Background()
	codex.Execute(ctx)
} 