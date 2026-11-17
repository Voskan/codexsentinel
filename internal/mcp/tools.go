package mcp

// tool describes one tool and its input schema.
type tool struct {
	name        string
	description string
	properties  map[string]map[string]any
	required    []string
}

var tools = []tool{
	{
		name:        "scan_path",
		description: "Analyze a Go module, package directory or file and return the findings in a compact text format: location, rule, CWE, reason, data flow, fix and patch.",
		properties: map[string]map[string]any{
			"path":      {"type": "string", "description": "Module directory, package directory or .go file to analyze"},
			"severity":  {"type": "string", "enum": []string{"low", "medium", "high", "critical"}, "description": "Report only findings at or above this severity"},
			"deps_only": {"type": "boolean", "description": "Run only the dependency audit"},
		},
		required: []string{"path"},
	},
	{
		name:        "scan_diff",
		description: "Analyze a Go module and report only findings on lines changed since a git reference, optionally failing on suppressions added in those changes.",
		properties: map[string]map[string]any{
			"path":                    {"type": "string", "description": "Module directory inside a git repository"},
			"git_ref":                 {"type": "string", "description": "Git reference to compare the working tree with, such as HEAD or origin/main"},
			"forbid_new_suppressions": {"type": "boolean", "description": "Report inline ignores, ignore-file entries and weaker settings added since git_ref"},
		},
		required: []string{"path", "git_ref"},
	},
	{
		name:        "verify_capabilities",
		description: "Check whether dependencies use capabilities (file system, network, exec, unsafe, ...) from reachable code that the capability lock file does not approve.",
		properties: map[string]map[string]any{
			"path":     {"type": "string", "description": "Module directory"},
			"lockfile": {"type": "string", "description": "Lock file, relative to the module root; default .codexsentinel.caps.json"},
		},
		required: []string{"path"},
	},
	{
		name:        "explain_rule",
		description: "Explain a rule: what it detects, why it matters, CWE and OWASP mapping, a vulnerable and a safe example, and how to suppress a reviewed finding.",
		properties: map[string]map[string]any{
			"rule": {"type": "string", "description": "Rule ID such as sql-injection, or code such as CS001"},
		},
		required: []string{"rule"},
	},
	{
		name:        "list_rules",
		description: "List the available rules with code, ID, default severity, category, CWE and title.",
		properties: map[string]map[string]any{
			"category": {"type": "string", "enum": []string{"security", "reliability", "supply-chain", "architecture", "metrics", "license", "suppression"}, "description": "Only rules of this category"},
		},
	},
}

func toolByName(name string) (tool, bool) {
	for _, t := range tools {
		if t.name == name {
			return t, true
		}
	}
	return tool{}, false
}

// toolList renders the tools for tools/list.
func toolList() []map[string]any {
	out := make([]map[string]any, len(tools))
	for i, t := range tools {
		schema := map[string]any{"type": "object", "properties": t.properties, "additionalProperties": false}
		if len(t.required) > 0 {
			schema["required"] = t.required
		}
		out[i] = map[string]any{
			"name":        t.name,
			"description": t.description,
			"inputSchema": schema,
			"annotations": map[string]any{"readOnlyHint": true, "openWorldHint": false},
		}
	}
	return out
}
