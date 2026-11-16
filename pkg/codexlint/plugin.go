package codexlint

import (
	"encoding/json"
	"fmt"

	"github.com/Voskan/codexsentinel/config"
	"golang.org/x/tools/go/analysis"
)

// Settings configures the analyzers built by New and NewPlugin. It mirrors
// the rule and suppression sections of the CodexSentinel configuration.
type Settings struct {
	Enabled            []string `json:"enabled"`
	Disabled           []string `json:"disabled"`
	MinConfidence      *float64 `json:"min_confidence"`
	EnableInlineIgnore *bool    `json:"enable_inline_ignore"`
}

// New builds the analyzers from loosely typed settings, such as the
// "settings" block of a golangci-lint custom linter. settings may be nil, a
// Settings value or any value that encodes to the Settings JSON shape.
func New(settings any) ([]*analysis.Analyzer, error) {
	cfg := config.NewDefaultConfig()
	if settings != nil {
		var s Settings
		switch v := settings.(type) {
		case Settings:
			s = v
		case *Settings:
			s = *v
		default:
			data, err := json.Marshal(settings)
			if err != nil {
				return nil, fmt.Errorf("codexlint settings: %w", err)
			}
			if err := json.Unmarshal(data, &s); err != nil {
				return nil, fmt.Errorf("codexlint settings: %w", err)
			}
		}
		if len(s.Enabled) > 0 {
			cfg.Rules.Enabled = s.Enabled
		}
		cfg.Rules.Disabled = append(cfg.Rules.Disabled, s.Disabled...)
		if s.MinConfidence != nil {
			cfg.Suppression.MinConfidence = *s.MinConfidence
		}
		if s.EnableInlineIgnore != nil {
			cfg.Suppression.EnableInlineIgnore = *s.EnableInlineIgnore
		}
	}
	return Analyzers(&cfg), nil
}

// Plugin implements the golangci-lint v2 module plugin contract
// (BuildAnalyzers and GetLoadMode) without depending on golangci-lint.
// Register it from a plugin module built with "golangci-lint custom":
//
//	func init() {
//		register.Plugin("codexsentinel", func(settings any) (register.LinterPlugin, error) {
//			return codexlint.NewPlugin(settings)
//		})
//	}
type Plugin struct {
	analyzers []*analysis.Analyzer
}

// NewPlugin builds a Plugin from golangci-lint settings.
func NewPlugin(settings any) (*Plugin, error) {
	analyzers, err := New(settings)
	if err != nil {
		return nil, err
	}
	return &Plugin{analyzers: analyzers}, nil
}

// BuildAnalyzers returns the configured analyzers.
func (p *Plugin) BuildAnalyzers() ([]*analysis.Analyzer, error) {
	return p.analyzers, nil
}

// GetLoadMode reports that the analyzers need type information.
func (p *Plugin) GetLoadMode() string {
	return "typesinfo"
}
