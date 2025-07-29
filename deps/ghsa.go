package deps

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

type GHSAResponse struct {
	Data struct {
		SecurityVulnerabilities struct {
			Nodes []struct {
				Package struct {
					Name string `json:"name"`
				} `json:"package"`
				Advisory struct {
					GHSAID   string `json:"ghsaId"`
					Summary  string `json:"summary"`
					Severity string `json:"severity"`
					Permalink string `json:"permalink"`
					References []struct {
						URL string `json:"url"`
					} `json:"references"`
				} `json:"advisory"`
				VulnerableVersionRange string `json:"vulnerableVersionRange"`
			} `json:"nodes"`
		} `json:"securityVulnerabilities"`
	} `json:"data"`
}

// FetchGHSAAdvisories fetches advisories from GitHub Advisory Database for Go modules in go.mod
func FetchGHSAAdvisories(goModPath string) ([]Vulnerability, error) {
	modules, err := ParseGoModModules(goModPath)
	if err != nil {
		return nil, err
	}
	var vulns []Vulnerability
	for _, mod := range modules {
		advs, err := fetchGHSAForModule(mod.Name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "GHSA fetch error for %s: %v\n", mod.Name, err)
			continue
		}
		vulns = append(vulns, advs...)
	}
	return vulns, nil
}

type GoModule struct {
	Name    string
	Version string
}

// ParseGoModModules parses go.mod and returns a list of modules
func ParseGoModModules(goModPath string) ([]GoModule, error) {
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, err
	}
	var mods []GoModule
	lines := bytes.Split(data, []byte("\n"))
	for _, line := range lines {
		fields := bytes.Fields(line)
		if len(fields) >= 2 && !bytes.HasPrefix(fields[0], []byte("module")) && !bytes.HasPrefix(fields[0], []byte("require")) && !bytes.HasPrefix(fields[0], []byte("replace")) && !bytes.HasPrefix(fields[0], []byte("exclude")) {
			mods = append(mods, GoModule{Name: string(fields[0]), Version: string(fields[1])})
		}
	}
	return mods, nil
}

func fetchGHSAForModule(module string) ([]Vulnerability, error) {
	query := `{"query": "query { securityVulnerabilities(first: 10, ecosystem: GO, package: { name: \"%s\" }) { nodes { package { name } advisory { ghsaId summary severity permalink references { url } } vulnerableVersionRange } } }"}`
	body := fmt.Sprintf(query, module)
	url := "https://api.github.com/graphql"
	
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN not set")
	}
	
	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub API error: %s", resp.Status)
	}
	var ghsaResp GHSAResponse
	if err := json.NewDecoder(resp.Body).Decode(&ghsaResp); err != nil {
		return nil, err
	}
	var vulns []Vulnerability
	for _, node := range ghsaResp.Data.SecurityVulnerabilities.Nodes {
		vulns = append(vulns, Vulnerability{
			Module:   node.Package.Name,
			ID:       node.Advisory.GHSAID,
			Details:  node.Advisory.Summary,
			Severity: node.Advisory.Severity,
			Reference: node.Advisory.Permalink,
			Aliases:  nil,
			Version:  "",
			FixedVersion: "",
		})
	}
	return vulns, nil
} 