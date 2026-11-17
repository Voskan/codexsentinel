package codex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	codessa "github.com/Voskan/codexsentinel/analyzer/ssa"
	"github.com/Voskan/codexsentinel/analyzer/workspace"
	"github.com/Voskan/codexsentinel/deps"
	"github.com/Voskan/codexsentinel/internal/version"
	"github.com/spf13/cobra"
)

type sbomOptions struct {
	format     string
	out        string
	vex        bool
	vexOut     string
	noCaps     bool
	offline    bool
	configFile string
}

// NewSBOMCmd returns the `sbom` command, which writes a CycloneDX or SPDX
// bill of materials and, with --vex, an OpenVEX document.
func NewSBOMCmd() *cobra.Command {
	opts := sbomOptions{}
	cmd := &cobra.Command{
		Use:   "sbom [path]",
		Short: "Write a CycloneDX or SPDX SBOM, and an OpenVEX document with --vex",
		Long: `Write a software bill of materials for the module at path.

Components carry package URLs, go.sum hashes, licenses and, unless --no-caps
is given, the capabilities their reachable code uses. With --vex, known
vulnerabilities are added and each one is marked by call graph reachability:
not affected when no vulnerable symbol is reachable. --vex-out also writes the
statements as an OpenVEX document for trivy or grype.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSBOM(cmd.Context(), targetArg(args), opts, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.format, "format", "cyclonedx", "SBOM format: cyclonedx or spdx")
	f.StringVar(&opts.out, "out", "-", "Output file; - writes to standard output")
	f.BoolVar(&opts.vex, "vex", false, "Add vulnerabilities with reachability-based VEX status")
	f.StringVar(&opts.vexOut, "vex-out", "", "Also write an OpenVEX document to this file (implies --vex)")
	f.BoolVar(&opts.noCaps, "no-caps", false, "Do not record dependency capabilities")
	f.BoolVar(&opts.offline, "offline", false, "Do not contact vulnerability databases")
	f.StringVar(&opts.configFile, "config", "", "Path to a custom config file")
	return cmd
}

func runSBOM(ctx context.Context, target string, opts sbomOptions, stdout, stderr io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.format != "cyclonedx" && opts.format != "spdx" {
		return fmt.Errorf("unknown SBOM format %q (want cyclonedx or spdx)", opts.format)
	}
	if opts.vexOut != "" {
		opts.vex = true
	}
	if opts.vex && opts.offline {
		return errors.New("--vex needs the vulnerability databases; it cannot be combined with --offline")
	}
	root, goMods, err := workspace.GoModFiles(target)
	if err != nil {
		return err
	}
	if len(goMods) != 1 {
		return fmt.Errorf("an SBOM describes one module, but %s is a go.work workspace of %d modules; run sbom in one of: %s",
			target, len(goMods), strings.Join(relativeDirs(root, goMods), ", "))
	}
	goModPath := goMods[0]
	sb, err := deps.ReadSBOM(goModPath)
	if err != nil {
		return err
	}
	sb.ToolVersion = version.Version
	if licenses, err := deps.AnalyzeLicenses(goModPath, nil, nil); err != nil {
		fmt.Fprintf(stderr, "Warning: licenses not detected: %v\n", err)
	} else {
		sb.SetLicenses(licenses)
	}
	var bundle *codessa.GraphBundle
	if !opts.noCaps || opts.vex {
		ws, b, err := loadProgram(ctx, root, opts.configFile)
		if err != nil {
			return err
		}
		bundle = b
		if !opts.noCaps {
			report, err := deps.AnalyzeCapabilities(ws, bundle)
			if err != nil {
				return err
			}
			sb.SetCapabilities(report)
		}
	}
	if opts.vex {
		vulns, err := deps.FindVulnerabilities(ctx, goModPath, bundle, deps.NewOSVClient())
		if err != nil {
			if len(vulns) == 0 {
				return err
			}
			fmt.Fprintf(stderr, "Warning: vulnerability lookup incomplete: %v\n", err)
		}
		sb.Vulns, sb.VulnsChecked = vulns, true
	}
	var doc any = sb.CycloneDX()
	if opts.format == "spdx" {
		doc = sb.SPDX()
	}
	if err := writeJSON(opts.out, doc, stdout); err != nil {
		return err
	}
	if opts.vexOut != "" {
		if err := writeJSON(opts.vexOut, sb.OpenVEX(), stdout); err != nil {
			return err
		}
		fmt.Fprintf(stderr, "Wrote %d VEX statements to %s\n", len(sb.Vulns), opts.vexOut)
	}
	return nil
}

// loadProgram loads the module containing target with the configuration of
// its project (see loadTargetConfig) and builds its SSA program.
func loadProgram(ctx context.Context, target, configFile string) (*workspace.Workspace, *codessa.GraphBundle, error) {
	loaded, err := loadTargetConfig(target, configFile, true)
	if err != nil {
		return nil, nil, err
	}
	ws, err := workspace.Load(ctx, loaded.Root, loaded.Config)
	if err != nil {
		return nil, nil, err
	}
	bundle, err := codessa.BuildFromWorkspace(ws)
	return ws, bundle, err
}

// writeJSON writes v as indented JSON to path, or to stdout for "-" or "".
func writeJSON(path string, v any, stdout io.Writer) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if path == "" || path == "-" {
		_, err = stdout.Write(data)
		return err
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, data, 0o644)
}

// relativeDirs returns the directories of files relative to root.
func relativeDirs(root string, files []string) []string {
	out := make([]string, 0, len(files))
	for _, f := range files {
		rel, err := filepath.Rel(root, filepath.Dir(f))
		if err != nil {
			rel = filepath.Dir(f)
		}
		out = append(out, filepath.ToSlash(rel))
	}
	return out
}
