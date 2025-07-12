package main

import (
	"context"

	"github.com/Voskan/codexsentinel/cmd/codex"
)

func main() {
	codex.Execute(context.Background())
} 