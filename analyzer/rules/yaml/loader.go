package yaml

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/printer"
	"go/token"
	"go/types"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/Voskan/codexsentinel/v2/analyzer"
	"github.com/Voskan/codexsentinel/v2/analyzer/result"
	"github.com/Voskan/codexsentinel/v2/analyzer/rules"
	"gopkg.in/yaml.v3"
)

// LoadFromDir compiles every YAML rule file under dir and registers the rules
// in the global registry, replacing rules with the same ID.
func LoadFromDir(dir string) error {
	compiled, err := CompileDir(dir)
	if err != nil {
		return err
	}
	return registerCompiled(compiled)
}

// LoadFromFile compiles a YAML rule file and registers its rules in the global
// registry, replacing rules with the same ID.
func LoadFromFile(path string) error {
	compiled, err := CompileFile(path)
	if err != nil {
		return err
	}
	return registerCompiled(compiled)
}

func registerCompiled(compiled []*CompiledRule) error {
	for _, c := range compiled {
		if err := rules.Upsert(c.Registration()); err != nil {
			return err
		}
	}
	return nil
}

// LoadFromFS compiles the rule files in dir of fsys, for example rules embedded
// in the binary. Files named example-*.yaml are samples and are skipped, as
// are rules with "enabled: false".
func LoadFromFS(fsys fs.FS, dir string) ([]*CompiledRule, error) {
	return compileFS(fsys, dir, true)
}

// CompileDir compiles every .yaml and .yml file under dir. Disabled rules are
// kept; their registry entries are marked as not enabled.
func CompileDir(dir string) ([]*CompiledRule, error) {
	compiled, err := compileFS(os.DirFS(dir), ".", false)
	if err != nil {
		return nil, fmt.Errorf("error loading rules from directory %q: %w", dir, err)
	}
	return compiled, nil
}

// CompileFile compiles the rules of one YAML file. Disabled rules are kept;
// their registry entries are marked as not enabled.
func CompileFile(path string) ([]*CompiledRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read rule file %q: %w", path, err)
	}
	return compileData(data, path, false)
}

// Registrations converts compiled rules to registry entries, in order.
func Registrations(compiled []*CompiledRule) []*rules.Rule {
	out := make([]*rules.Rule, len(compiled))
	for i, c := range compiled {
		out[i] = c.Registration()
	}
	return out
}

func compileFS(fsys fs.FS, dir string, builtin bool) ([]*CompiledRule, error) {
	var out []*CompiledRule
	err := fs.WalkDir(fsys, dir, func(name string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		ext := path.Ext(name)
		if d.IsDir() || (ext != ".yaml" && ext != ".yml") {
			return nil
		}
		if builtin && strings.HasPrefix(d.Name(), "example-") {
			return nil
		}
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return fmt.Errorf("failed to read rule file %q: %w", name, err)
		}
		compiled, err := compileData(data, name, builtin)
		if err != nil {
			return err
		}
		out = append(out, compiled...)
		return nil
	})
	return out, err
}

func compileData(data []byte, name string, dropDisabled bool) ([]*CompiledRule, error) {
	parsed, err := ParseRules(data, name)
	if err != nil {
		return nil, err
	}
	var out []*CompiledRule
	for _, rule := range parsed {
		compiled, err := Compile(rule)
		if err != nil {
			return nil, fmt.Errorf("invalid rule %q in %q: %w", rule.ID, name, err)
		}
		if rule.IsEnabled() || !dropDisabled {
			out = append(out, compiled)
		}
	}
	return out, nil
}

// ParseRules decodes a rule file. A file holds one rule per YAML document, or
// a document with a top-level "rules" list.
func ParseRules(data []byte, path string) ([]RuleYAML, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var out []RuleYAML
	for {
		var node yaml.Node
		err := dec.Decode(&node)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse YAML in %q: %w", path, err)
		}
		if len(node.Content) == 0 {
			continue
		}
		var list struct {
			Rules []RuleYAML `yaml:"rules"`
		}
		if err := node.Decode(&list); err == nil && len(list.Rules) > 0 {
			out = append(out, list.Rules...)
			continue
		}
		var rule RuleYAML
		if err := node.Decode(&rule); err != nil {
			return nil, fmt.Errorf("failed to parse YAML in %q: %w", path, err)
		}
		out = append(out, rule)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("invalid rule file %q: no rules found", path)
	}
	for _, r := range out {
		if r.ID == "" {
			return nil, fmt.Errorf("invalid rule in %q: missing required field 'id'", path)
		}
		if r.pattern() == "" {
			return nil, fmt.Errorf("invalid rule %q in %q: missing required field 'pattern' or 'match.pattern'", r.ID, path)
		}
	}
	return out, nil
}

func (r RuleYAML) pattern() string {
	if r.Match != nil && r.Match.Pattern != "" {
		return r.Match.Pattern
	}
	return r.Pattern
}

// CompiledRule is a YAML rule with its patterns parsed and filters validated.
type CompiledRule struct {
	Rule     RuleYAML
	Pattern  *Pattern
	Not      []*Pattern
	filters  []compiledFilter
	severity result.Severity
}

type compiledFilter struct {
	Filter
	name    string
	include []*regexp.Regexp
	exclude []*regexp.Regexp
}

// Compile parses the rule's patterns and filters once.
func Compile(rule RuleYAML) (*CompiledRule, error) {
	if rule.Category == "" {
		rule.Category = "security"
	}
	if rule.Severity == "" {
		rule.Severity = "MEDIUM"
	}
	p, err := CompilePattern(rule.pattern())
	if err != nil {
		return nil, err
	}
	c := &CompiledRule{Rule: rule, Pattern: p, severity: result.ParseSeverity(rule.Severity)}
	if rule.Match != nil {
		for _, src := range rule.Match.NotPattern {
			np, err := CompilePattern(src)
			if err != nil {
				return nil, fmt.Errorf("not_pattern: %w", err)
			}
			c.Not = append(c.Not, np)
		}
		for _, f := range rule.Match.Filters {
			cf := compiledFilter{Filter: f, name: strings.TrimPrefix(strings.Trim(strings.TrimSpace(f.Var), "{}"), "$")}
			switch f.Type {
			case "import", "package":
			case "type", "non_const":
				if cf.name == "" {
					return nil, fmt.Errorf("%s filter needs 'var'", f.Type)
				}
			case "regex":
				if cf.name == "" {
					return nil, errors.New("regex filter needs 'var'")
				}
				for _, list := range []struct {
					src []string
					dst *[]*regexp.Regexp
				}{{f.Include, &cf.include}, {f.Exclude, &cf.exclude}} {
					for _, expr := range list.src {
						re, err := regexp.Compile(expr)
						if err != nil {
							return nil, fmt.Errorf("regex filter: %w", err)
						}
						*list.dst = append(*list.dst, re)
					}
				}
			case "file_ext", "param", "call":
				// Accepted for compatibility with older rule files; Go sources only.
				continue
			default:
				return nil, fmt.Errorf("unknown filter type %q", f.Type)
			}
			c.filters = append(c.filters, cf)
		}
	}
	if rule.Fix != "" {
		if _, err := CompilePattern(rule.Fix); err != nil {
			return nil, fmt.Errorf("fix: %w", err)
		}
	}
	return c, nil
}

// Registration returns the registry entry for the rule.
func (c *CompiledRule) Registration() *rules.Rule {
	r := c.Rule
	return &rules.Rule{
		ID:          r.ID,
		Title:       r.Title,
		Category:    r.Category,
		Severity:    r.Severity,
		Description: r.Description,
		Suggestion:  r.Suggestion,
		References:  r.References,
		YAML:        &rules.YAMLRule{Pattern: r.pattern()},
		Enabled:     r.IsEnabled(),
		Engine:      c.Run,
		Fingerprint: c.fingerprint(),
	}
}

// fingerprint hashes the rule definition, so that cached results of an edited
// rule are not reused.
func (c *CompiledRule) fingerprint() string {
	data, err := json.Marshal(c.Rule)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Run matches the rule against the files of one package.
func (c *CompiledRule) Run(ac *analyzer.AnalyzerContext) ([]result.Issue, error) {
	if ac == nil || ac.Fset == nil {
		return nil, nil
	}
	var issues []result.Issue
	for _, file := range ac.Files {
		if !c.fileAllowed(ac, file) {
			continue
		}
		for _, m := range c.Pattern.FindAll(ac.Types, file) {
			if !c.accept(ac, m) {
				continue
			}
			issues = append(issues, c.issue(ac, m))
		}
	}
	return issues, nil
}

func (c *CompiledRule) fileAllowed(ac *analyzer.AnalyzerContext, file *ast.File) bool {
	for _, f := range c.filters {
		switch f.Type {
		case "import":
			if !importsAny(file, f.Include) {
				return false
			}
		case "package":
			names := []string{file.Name.Name, ac.PackageName}
			if len(f.Allow) > 0 && !packageMatches(f.Allow, names) {
				return false
			}
			if packageMatches(f.Exclude, names) {
				return false
			}
		}
	}
	return true
}

func importsAny(file *ast.File, paths []string) bool {
	for _, imp := range file.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		for _, want := range paths {
			if p == want {
				return true
			}
		}
	}
	return false
}

// packageMatches reports whether a glob matches a package name or any
// trailing segment sequence of a package path ("service/*" matches
// "example.com/app/service/user").
func packageMatches(globs, names []string) bool {
	for _, glob := range globs {
		for _, name := range names {
			if name == "" {
				continue
			}
			segs := strings.Split(name, "/")
			for i := range segs {
				if ok, _ := path.Match(glob, strings.Join(segs[i:], "/")); ok {
					return true
				}
			}
		}
	}
	return false
}

func (c *CompiledRule) accept(ac *analyzer.AnalyzerContext, m Match) bool {
	for _, f := range c.filters {
		node, ok := m.Bindings[f.name]
		switch f.Type {
		case "type":
			expr, isExpr := node.(ast.Expr)
			if !ok || !isExpr || ac.Types == nil {
				return false
			}
			t := ac.Types.TypeOf(expr)
			if t == nil || !typeListed(t, f.Include) {
				return false
			}
		case "non_const":
			expr, isExpr := node.(ast.Expr)
			if !ok || !isExpr || isConstant(ac.Types, expr) {
				return false
			}
		case "regex":
			if !ok {
				return false
			}
			text := nodeText(ac.Fset, node)
			if len(f.include) > 0 && !anyMatch(f.include, text) || anyMatch(f.exclude, text) {
				return false
			}
		}
	}
	for _, np := range c.Not {
		suppressed := false
		ast.Inspect(m.Node, func(n ast.Node) bool {
			if suppressed || n == nil {
				return false
			}
			if _, ok := np.Match(ac.Types, n, m.Bindings); ok {
				suppressed = true
			}
			return !suppressed
		})
		if suppressed {
			return false
		}
	}
	return true
}

func typeListed(t types.Type, names []string) bool {
	s := types.TypeString(t, nil)
	for _, n := range names {
		if s == n {
			return true
		}
	}
	return false
}

func isConstant(info *types.Info, e ast.Expr) bool {
	if info == nil {
		_, ok := e.(*ast.BasicLit)
		return ok
	}
	tv, ok := info.Types[e]
	return ok && tv.Value != nil
}

func anyMatch(res []*regexp.Regexp, s string) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// nodeText prints a node as Go source.
func nodeText(fset *token.FileSet, n ast.Node) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, n); err != nil {
		return ""
	}
	return buf.String()
}

func (c *CompiledRule) issue(ac *analyzer.AnalyzerContext, m Match) result.Issue {
	r := c.Rule
	pos, end := ac.Fset.Position(m.Node.Pos()), ac.Fset.Position(m.Node.End())
	loc := result.NewLocationFromPos(pos, "", ac.PackageName)
	loc.EndLine, loc.EndColumn = end.Line, end.Column
	desc := strings.TrimSpace(r.Description)
	if desc == "" {
		desc = r.Title
	}
	issue := result.Issue{
		ID:          r.ID,
		Title:       r.Title,
		Description: desc,
		Severity:    c.severity,
		Confidence:  1,
		CWE:         r.CWE,
		Location:    loc,
		Category:    r.Category,
		Suggestion:  r.Suggestion,
		References:  r.References,
	}
	if r.Fix != "" {
		issue.Fix = buildFix(ac.Fset, m, r.Fix, firstNonEmpty(r.Suggestion, r.Title, "Apply suggested fix"))
	}
	return issue
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
