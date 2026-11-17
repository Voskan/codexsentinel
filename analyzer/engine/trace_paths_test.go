package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Voskan/codexsentinel/config"
)

// Traces of every analysis, not only the taint engine, use paths relative to
// the module root, like the finding locations.
func TestTracePathsAreRelative(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.test/orders\n\ngo 1.24\n",
		"orders.go": `package orders

import (
	"context"
	"database/sql"
	"net/http"
)

func charge(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://pay.example.com/charge", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func Pay(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := charge(ctx); err != nil {
		return err
	}
	return tx.Commit()
}
`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.NewDefaultConfig()
	cfg.Scan.EnableCache = false
	issues, err := Run(context.Background(), dir, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, is := range issues {
		if is.ID != "tx-network-io" {
			continue
		}
		found = true
		if len(is.Trace) == 0 {
			t.Fatal("tx-network-io finding has no trace")
		}
		for _, step := range is.Trace {
			if step.Location.File != "orders.go" {
				t.Errorf("trace step at %q, want orders.go", step.Location.File)
			}
		}
	}
	if !found {
		t.Fatalf("tx-network-io not reported: %+v", issues)
	}
}
