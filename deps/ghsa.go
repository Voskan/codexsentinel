package deps

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// GHSAClient queries the GitHub Advisory Database GraphQL API.
type GHSAClient struct {
	URL   string // GraphQL endpoint, https://api.github.com/graphql by default
	Token string // GitHub token; queries are skipped without one
	HTTP  *http.Client
}

// NewGHSAClient returns a client authenticated with $GITHUB_TOKEN.
func NewGHSAClient() *GHSAClient {
	return &GHSAClient{URL: "https://api.github.com/graphql", Token: os.Getenv("GITHUB_TOKEN"), HTTP: &http.Client{Timeout: 10 * time.Second}}
}

const ghsaQuery = `query($pkg: String!) {
  securityVulnerabilities(first: 100, ecosystem: GO, package: $pkg) {
    nodes {
      package { name }
      advisory { ghsaId summary description severity permalink identifiers { type value } }
      vulnerableVersionRange
      firstPatchedVersion { identifier }
    }
  }
}`

type ghsaResponse struct {
	Data struct {
		SecurityVulnerabilities struct {
			Nodes []struct {
				Package struct {
					Name string `json:"name"`
				} `json:"package"`
				Advisory struct {
					GHSAID      string `json:"ghsaId"`
					Summary     string `json:"summary"`
					Description string `json:"description"`
					Severity    string `json:"severity"`
					Permalink   string `json:"permalink"`
					Identifiers []struct {
						Type  string `json:"type"`
						Value string `json:"value"`
					} `json:"identifiers"`
				} `json:"advisory"`
				VulnerableVersionRange string `json:"vulnerableVersionRange"`
				FirstPatchedVersion    *struct {
					Identifier string `json:"identifier"`
				} `json:"firstPatchedVersion"`
			} `json:"nodes"`
		} `json:"securityVulnerabilities"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// Audit returns GitHub advisories whose vulnerable range contains the module
// versions. Without a token it returns no results: OSV already includes the
// GitHub Advisory Database for Go.
func (c *GHSAClient) Audit(ctx context.Context, mods []ModuleVersion) ([]Vulnerability, error) {
	if c.Token == "" {
		return nil, nil
	}
	var out []Vulnerability
	for _, mod := range mods {
		if mod.Path == StdlibModule {
			continue
		}
		found, err := c.query(ctx, mod)
		if err != nil {
			return out, err
		}
		out = append(out, found...)
	}
	return out, nil
}

func (c *GHSAClient) query(ctx context.Context, mod ModuleVersion) ([]Vulnerability, error) {
	body, err := json.Marshal(map[string]any{"query": ghsaQuery, "variables": map[string]string{"pkg": mod.Path}})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API error: %s", resp.Status)
	}
	var parsed ghsaResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&parsed); err != nil {
		return nil, err
	}
	if len(parsed.Errors) > 0 {
		return nil, fmt.Errorf("GitHub API error: %s", parsed.Errors[0].Message)
	}
	var out []Vulnerability
	for _, node := range parsed.Data.SecurityVulnerabilities.Nodes {
		ok, err := MatchGHSARange(node.VulnerableVersionRange, mod.Version)
		if err != nil || !ok {
			continue
		}
		v := Vulnerability{Module: mod.Required, Version: mod.Version, ID: node.Advisory.GHSAID, Summary: node.Advisory.Summary,
			Details: node.Advisory.Description, Severity: normalizeSeverity(node.Advisory.Severity), Reference: node.Advisory.Permalink}
		for _, id := range node.Advisory.Identifiers {
			if id.Value != node.Advisory.GHSAID {
				v.Aliases = append(v.Aliases, id.Value)
			}
		}
		if node.FirstPatchedVersion != nil {
			v.FixedVersion = node.FirstPatchedVersion.Identifier
			if !strings.HasPrefix(v.FixedVersion, "v") {
				v.FixedVersion = "v" + v.FixedVersion
			}
		}
		out = append(out, v)
	}
	return out, nil
}
