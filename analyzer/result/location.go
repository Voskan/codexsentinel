package result

import (
	"fmt"
	"go/token"
)

// Location represents the position in the source code where an issue was found.
type Location struct {
	File        string `json:"file"`        // Path to the file
	Line        int    `json:"line"`        // Line number in the file (1-based)
	Column      int    `json:"column"`      // Column number in the line (1-based)
	Function    string `json:"function"`    // Function or method name (optional)
	PackagePath string `json:"package"`     // Go package path (e.g., github.com/user/project/foo)
}

// NewLocationFromPos creates a Location from a token.Position and optional metadata.
func NewLocationFromPos(pos token.Position, fallbackFile, fallbackPkg string) Location {
	return Location{
		File: pos.Filename,
		Line: pos.Line,
		Column: pos.Column,
		Function: "", // No function name in this context
		PackagePath: fallbackPkg, // Use fallback if no package path is available
	}
}

// String returns a human-readable string for the location.
func (l Location) String() string {
	if l.Function != "" {
		return fmt.Sprintf("%s:%d:%d in %s()", l.File, l.Line, l.Column, l.Function)
	}
	return fmt.Sprintf("%s:%d:%d", l.File, l.Line, l.Column)
}
