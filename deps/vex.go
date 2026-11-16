package deps

import (
	"fmt"
	"strings"
	"time"
)

// OpenVEXContext is the JSON-LD context of OpenVEX v0.2.0 documents.
const OpenVEXContext = "https://openvex.dev/ns/v0.2.0"

// OpenVEXDocument is an OpenVEX v0.2.0 document.
type OpenVEXDocument struct {
	Context    string             `json:"@context"`
	ID         string             `json:"@id"`
	Author     string             `json:"author"`
	Timestamp  string             `json:"timestamp"`
	Version    int                `json:"version"`
	Tooling    string             `json:"tooling,omitempty"`
	Statements []OpenVEXStatement `json:"statements"`
}

// OpenVEXStatement states the impact of one vulnerability on the product.
type OpenVEXStatement struct {
	Vulnerability   OpenVEXVulnerability `json:"vulnerability"`
	Products        []OpenVEXProduct     `json:"products"`
	Status          string               `json:"status"`
	Justification   string               `json:"justification,omitempty"`
	ImpactStatement string               `json:"impact_statement,omitempty"`
	ActionStatement string               `json:"action_statement,omitempty"`
}

type OpenVEXVulnerability struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
}

type OpenVEXProduct struct {
	ID            string                `json:"@id"`
	Subcomponents []OpenVEXSubcomponent `json:"subcomponents,omitempty"`
}

type OpenVEXSubcomponent struct {
	ID string `json:"@id"`
}

// OpenVEX states, for every vulnerability, whether the module is affected,
// based on call graph reachability.
func (s *SBOM) OpenVEX() *OpenVEXDocument {
	doc := &OpenVEXDocument{
		Context:    OpenVEXContext,
		ID:         "urn:uuid:" + deterministicUUID(append([]string{"openvex"}, s.identity()...)...),
		Author:     "CodexSentinel Static Reachability Engine",
		Timestamp:  s.Timestamp.UTC().Format(time.RFC3339),
		Version:    1,
		Tooling:    strings.TrimSpace(s.toolName() + " " + s.ToolVersion),
		Statements: []OpenVEXStatement{},
	}
	versions := map[string]string{}
	for _, c := range s.Components {
		versions[c.Module] = c.Version
	}
	for _, v := range s.Vulns {
		version := versions[v.Module]
		if version == "" {
			version = v.Version
		}
		name, aliases := primaryVulnID(v)
		st := OpenVEXStatement{
			Vulnerability: OpenVEXVulnerability{Name: name, Description: v.Summary, Aliases: aliases},
			Products:      []OpenVEXProduct{{ID: s.rootPURL(), Subcomponents: []OpenVEXSubcomponent{{ID: PURL(v.Module, version)}}}},
		}
		switch {
		case v.Reachable != nil && !*v.Reachable:
			st.Status = "not_affected"
			st.Justification = "vulnerable_code_not_in_execute_path"
			st.ImpactStatement = notReachableStatement(v)
		case v.Reachable != nil:
			st.Status = "affected"
			st.ActionStatement = actionStatement(v)
		default:
			st.Status = "under_investigation"
		}
		doc.Statements = append(doc.Statements, st)
	}
	return doc
}

// primaryVulnID prefers a CVE identifier and returns the other identifiers
// as aliases.
func primaryVulnID(v Vulnerability) (string, []string) {
	name := v.ID
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			name = a
			break
		}
	}
	var aliases []string
	for _, id := range append([]string{v.ID}, v.Aliases...) {
		if id != name && !containsString(aliases, id) {
			aliases = append(aliases, id)
		}
	}
	return name, aliases
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func notReachableStatement(v Vulnerability) string {
	return "Static VTA call-graph analysis verified that vulnerable symbols of " + v.Module + " are not reachable from any program entrypoint."
}

func actionStatement(v Vulnerability) string {
	out := "Upgrade " + v.Module
	if v.FixedVersion != "" {
		out += " to " + v.FixedVersion + " or later"
	}
	out += "."
	if v.Symbol != "" {
		out += fmt.Sprintf(" The vulnerable symbol %s is reachable", v.Symbol)
		if v.CalledBy != "" {
			out += " from " + v.CalledBy
		}
		out += "."
	}
	return out
}
