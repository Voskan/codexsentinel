package formats

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Voskan/codexsentinel/report"
)

// WriteJSONReport serializes the provided issues into a pretty JSON format and writes them to a file.
func WriteJSONReport(issues []report.Issue, path string) error {
	data, err := json.MarshalIndent(issues, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal issues to JSON: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write JSON report to file: %w", err)
	}

	return nil
}
