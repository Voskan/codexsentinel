package flow

import (
	"strings"

	"github.com/Voskan/codexsentinel/config"
)

// DefaultRegistry returns the built-in catalog of sources, sinks and sanitizers.
func DefaultRegistry() *Registry {
	return &Registry{
		Sources:    builtinSources(),
		Sinks:      builtinSinks(),
		Sanitizers: builtinSanitizers(),
		Categories: builtinCategories(),
	}
}

// RegistryFromConfig extends the built-in catalog with user-defined specifications.
func RegistryFromConfig(cfg config.TaintConfig) *Registry {
	reg := DefaultRegistry()
	for _, s := range cfg.CustomSources {
		reg.Sources = append(reg.Sources, SourceSpec{Package: s.Package, Receiver: normalizeReceiver(s.Receiver), Function: s.Function, Tags: s.Tags, Description: "custom source"})
	}
	for _, s := range cfg.CustomSinks {
		category := s.Category
		if category == "" {
			category = "tainted-data"
		}
		spec := SinkSpec{Package: s.Package, Receiver: normalizeReceiver(s.Receiver), Function: s.Function, CheckArgs: s.CheckArgs, WriterArg: -1, Category: category, Description: "custom sink " + s.Function}
		spec.AllArgs = len(s.CheckArgs) == 0
		reg.Sinks = append(reg.Sinks, spec)
	}
	for _, s := range cfg.CustomSanitizers {
		categories := s.Categories
		if len(categories) == 0 {
			categories = []string{"*"}
		}
		reg.Sanitizers = append(reg.Sanitizers, SanitizerSpec{Package: s.Package, Receiver: normalizeReceiver(s.Receiver), Function: s.Function, Categories: categories})
	}
	return reg
}

func normalizeReceiver(r string) string {
	r = strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(r), "*"))
	if i := strings.LastIndexByte(r, '.'); i >= 0 {
		r = r[i+1:]
	}
	return r
}
