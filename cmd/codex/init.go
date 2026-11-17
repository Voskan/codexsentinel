package codex

import (
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	goversion "go/version"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Voskan/codexsentinel/analyzer/workspace"
	"github.com/Voskan/codexsentinel/config"
	"github.com/Voskan/codexsentinel/deps"
	"github.com/spf13/cobra"
	"golang.org/x/mod/modfile"
)

// NewInitCmd returns the `init` command, which writes a configuration
// tailored to the module's layout and libraries.
func NewInitCmd() *cobra.Command {
	var force, withCaps bool
	cmd := &cobra.Command{
		Use:   "init [path]",
		Short: "Write a .codexsentinel.yaml tailored to the module's layout and libraries",
		Long: `Inspect go.mod and the directory tree, then write .codexsentinel.yaml with
architecture layers for the directories found (handler, service, domain,
repository and their synonyms), exclusions for generated code and mocks, and
an empty .codexsentinel.ignore. An existing configuration is kept unless
--force is given. --with-caps also records the dependency capability lock.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInit(cmd, targetArg(args), force, withCaps)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite an existing configuration")
	cmd.Flags().BoolVar(&withCaps, "with-caps", false, "Also write .codexsentinel.caps.json")
	return cmd
}

// projectProfile is what init learns about a module.
type projectProfile struct {
	Module     string
	GoVersion  string
	Frameworks []string
	// Layers maps layer names to the directories assigned to them.
	Layers   map[string][]string
	Excludes []string
}

func runInit(cmd *cobra.Command, target string, force, withCaps bool) error {
	root, err := workspace.ProjectRoot(target)
	if err != nil {
		return err
	}
	if existing := config.FindDefaultConfigFile(root); existing != "" && !force {
		return fmt.Errorf("%s already exists; use --force to overwrite it", existing)
	}
	profile, err := inspectProject(root)
	if err != nil {
		return err
	}
	path := filepath.Join(root, config.DefaultConfigFilename)
	if err := os.WriteFile(path, []byte(renderConfig(profile)), 0o644); err != nil {
		return err
	}
	if _, err := config.LoadFromPath(path); err != nil {
		return fmt.Errorf("generated configuration is invalid: %w", err)
	}
	ignorePath := filepath.Join(root, ".codexsentinel.ignore")
	if _, err := os.Stat(ignorePath); errors.Is(err, fs.ErrNotExist) {
		if err := os.WriteFile(ignorePath, []byte(ignoreTemplate), 0o644); err != nil {
			return err
		}
	}
	out := cmd.OutOrStdout()
	printProfile(out, profile)
	fmt.Fprintf(out, "Wrote %s\n", path)
	if withCaps {
		report, _, err := capabilityReport(cmd.Context(), root, path)
		if err != nil {
			return fmt.Errorf("capability lock: %w", err)
		}
		lockPath := resolveLockfile(root, "")
		if err := deps.WriteCapabilityLock(lockPath, report.Lock()); err != nil {
			return err
		}
		fmt.Fprintf(out, "Wrote capabilities of %d modules to %s\n", len(report.Modules), lockPath)
	}
	return nil
}

const ignoreTemplate = `# Findings to ignore, one entry per line, relative to the module root.
# Examples:
#   internal/legacy/** sql-injection   # a rule under a path
#   cmd/tool/main.go:42 path-traversal # a single line
#   **/*.pb.go                         # every rule under a path
`

// frameworkModules maps module path prefixes to short library names.
var frameworkModules = []struct{ prefix, name string }{
	{"github.com/gin-gonic/gin", "gin"}, {"github.com/labstack/echo", "echo"}, {"github.com/gofiber/fiber", "fiber"},
	{"github.com/go-chi/chi", "chi"}, {"github.com/gorilla/mux", "gorilla/mux"}, {"google.golang.org/grpc", "grpc"},
	{"connectrpc.com/connect", "connect"}, {"github.com/99designs/gqlgen", "gqlgen"}, {"github.com/jackc/pgx", "pgx"},
	{"gorm.io/gorm", "gorm"}, {"github.com/jmoiron/sqlx", "sqlx"}, {"github.com/lib/pq", "pq"},
	{"github.com/go-sql-driver/mysql", "mysql"}, {"go.mongodb.org/mongo-driver", "mongo"}, {"github.com/redis/go-redis", "redis"},
	{"go.uber.org/zap", "zap"}, {"github.com/rs/zerolog", "zerolog"}, {"github.com/sirupsen/logrus", "logrus"},
	{"github.com/golang-jwt/jwt", "jwt"},
}

// layerDirs maps directory names to layers. Plurals are accepted too.
var layerDirs = map[string]string{
	"handler": "delivery", "controller": "delivery", "delivery": "delivery", "transport": "delivery", "api": "delivery", "rest": "delivery", "grpc": "delivery",
	"usecase": "service", "service": "service", "application": "service", "app": "service",
	"domain": "domain", "entity": "domain", "entities": "domain", "model": "domain",
	"repository": "repository", "repositories": "repository", "repo": "repository", "storage": "repository", "store": "repository",
	"infra": "repository", "infrastructure": "repository", "adapter": "repository", "persistence": "repository",
}

// layerDeps lists the layers each layer may import, in dependency order.
var layerDeps = []struct {
	layer string
	deps  []string
}{
	{"delivery", []string{"service", "domain"}},
	{"service", []string{"domain", "repository"}},
	{"repository", []string{"domain"}},
	{"domain", nil},
}

var skipDirs = map[string]bool{"vendor": true, "testdata": true, "node_modules": true, ".git": true}

// readModules fills the module path and Go version of p from the go.mod of
// the module at root, or of every module of the go.work workspace there, and
// returns the frameworks their requirements name.
func readModules(root string, p *projectProfile) (map[string]bool, error) {
	_, goMods, err := workspace.GoModFiles(root)
	if err != nil {
		return nil, fmt.Errorf("init needs a Go module or go.work workspace: %w", err)
	}
	var modules []string
	found := map[string]bool{}
	for _, goMod := range goMods {
		data, err := os.ReadFile(goMod)
		if err != nil {
			return nil, err
		}
		f, err := modfile.Parse(goMod, data, nil)
		if err != nil {
			return nil, err
		}
		if f.Module != nil {
			modules = append(modules, f.Module.Mod.Path)
		}
		if f.Go != nil && (p.GoVersion == "" || goversion.Compare("go"+f.Go.Version, "go"+p.GoVersion) > 0) {
			p.GoVersion = f.Go.Version
		}
		for _, req := range f.Require {
			for _, fw := range frameworkModules {
				if req.Mod.Path == fw.prefix || strings.HasPrefix(req.Mod.Path, fw.prefix+"/") {
					found[fw.name] = true
				}
			}
		}
	}
	p.Module = strings.Join(modules, ", ")
	return found, nil
}

func inspectProject(root string) (*projectProfile, error) {
	p := &projectProfile{Layers: map[string][]string{}}
	found, err := readModules(root, p)
	if err != nil {
		return nil, err
	}
	excludes := map[string]bool{}
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		depth := strings.Count(rel, "/") + 1
		if d.IsDir() {
			if rel == "." {
				return nil
			}
			name := d.Name()
			if skipDirs[name] || strings.HasPrefix(name, ".") || depth > 4 {
				return filepath.SkipDir
			}
			switch name {
			case "mocks", "mock":
				excludes["**/"+name+"/**"] = true
			case "gen", "generated":
				excludes["**/"+name+"/**"] = true
			}
			if layer, ok := layerOfDir(name); ok && depth <= 3 && !nestedInLayer(p.Layers, rel) {
				p.Layers[layer] = append(p.Layers[layer], rel)
			}
			return nil
		}
		if strings.HasSuffix(path, ".pb.go") {
			excludes["**/*.pb.go"] = true
		}
		if strings.HasSuffix(path, ".go") && !found["slog"] && importsSlog(path) {
			found["slog"] = true
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	for name := range found {
		p.Frameworks = append(p.Frameworks, name)
	}
	sort.Strings(p.Frameworks)
	for e := range excludes {
		p.Excludes = append(p.Excludes, e)
	}
	sort.Strings(p.Excludes)
	if len(p.Layers) < 2 {
		p.Layers = map[string][]string{} // one layer alone does not describe an architecture
	}
	return p, nil
}

func layerOfDir(name string) (string, bool) {
	if layer, ok := layerDirs[name]; ok {
		return layer, true
	}
	layer, ok := layerDirs[strings.TrimSuffix(name, "s")]
	return layer, ok
}

// nestedInLayer reports whether rel lies below a directory already assigned
// to a layer, such as internal/domain/model.
func nestedInLayer(layers map[string][]string, rel string) bool {
	for _, dirs := range layers {
		for _, d := range dirs {
			if strings.HasPrefix(rel, d+"/") {
				return true
			}
		}
	}
	return false
}

func importsSlog(path string) bool {
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		return false
	}
	for _, imp := range f.Imports {
		if imp.Path.Value == `"log/slog"` {
			return true
		}
	}
	return false
}

func renderConfig(p *projectProfile) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# CodexSentinel configuration for %s, generated by codex-cli init.\n", p.Module)
	b.WriteString("# Settings not listed here keep their defaults; see the configuration reference.\n")
	b.WriteString("version: 1\n\nscan:\n")
	b.WriteString("  # Directories and files that are never analyzed.\n")
	excludes := append([]string{"vendor", "testdata", "node_modules", ".git"}, p.Excludes...)
	fmt.Fprintf(&b, "  excluded_paths: [%s]\n", quoteList(excludes))
	b.WriteString("  enable_cache: true\n\nrules:\n  enabled: [\"*\"]\n  disabled: []\n\n")
	b.WriteString("architecture:\n  enable: true\n")
	if len(p.Layers) == 0 {
		b.WriteString("  # No layered layout was found; import cycles and oversized structs are\n")
		b.WriteString("  # still checked. Add layers and allowed_deps to enforce boundaries.\n")
	} else {
		b.WriteString("  # Layers found in the directory tree. A package belongs to a layer when its\n")
		b.WriteString("  # path is one of these directories or lies below one.\n  layers:\n")
		for _, ld := range layerDeps {
			if dirs, ok := p.Layers[ld.layer]; ok {
				sort.Strings(dirs)
				fmt.Fprintf(&b, "    %s: [%s]\n", ld.layer, quoteList(dirs))
			}
		}
		b.WriteString("  # The layers each layer may import.\n  allowed_deps:\n")
		for _, ld := range layerDeps {
			if _, ok := p.Layers[ld.layer]; ok {
				fmt.Fprintf(&b, "    %s: [%s]\n", ld.layer, quoteList(presentLayers(p, ld.deps)))
			}
		}
	}
	b.WriteString("  check_cycles: true\n  check_god_structs: true\n  check_boundaries: true\n\n")
	b.WriteString("dependencies:\n")
	b.WriteString("  # The vulnerability audit queries OSV and the module proxy; enable it in CI.\n")
	b.WriteString("  enable: false\n  check_vulnerabilities: true\n  check_reachability: true\n")
	b.WriteString("  # go.mod checks run on every scan: typosquatting, local replace, go.sum.\n")
	b.WriteString("  check_provenance: true\n  check_hygiene: true\n  min_module_age_days: 7\n")
	b.WriteString("  allowed_prefixes: []\n  denied_prefixes: []\n\n")
	b.WriteString("suppression:\n  ignore_file: .codexsentinel.ignore\n  enable_inline_ignore: true\n  require_ignore_reason: true\n\n")
	b.WriteString("report:\n  formats: [sarif]\n  output_dir: scan_reports\n")
	return b.String()
}

func presentLayers(p *projectProfile, layers []string) []string {
	out := []string{}
	for _, l := range layers {
		if _, ok := p.Layers[l]; ok {
			out = append(out, l)
		}
	}
	return out
}

func quoteList(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = strconv.Quote(s)
	}
	return strings.Join(quoted, ", ")
}

func printProfile(w io.Writer, p *projectProfile) {
	goVersion := p.GoVersion
	if goVersion == "" {
		goVersion = "(unknown)"
	}
	frameworks := "none"
	if len(p.Frameworks) > 0 {
		frameworks = strings.Join(p.Frameworks, ", ")
	}
	layers := "none found"
	if len(p.Layers) > 0 {
		var edges []string
		for _, ld := range layerDeps {
			if _, ok := p.Layers[ld.layer]; ok {
				if deps := presentLayers(p, ld.deps); len(deps) > 0 {
					edges = append(edges, ld.layer+" -> "+strings.Join(deps, ", "))
				} else {
					edges = append(edges, ld.layer)
				}
			}
		}
		layers = strings.Join(edges, "; ")
	}
	kind := "module"
	if strings.Contains(p.Module, ", ") {
		kind = "workspace modules"
	}
	fmt.Fprintf(w, "Detected Go %s %s %s\n  libraries: %s\n  layers:    %s\n", goVersion, kind, p.Module, frameworks, layers)
}
