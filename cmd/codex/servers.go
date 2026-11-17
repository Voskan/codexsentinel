package codex

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Voskan/codexsentinel/analyzer/engine"
	"github.com/Voskan/codexsentinel/analyzer/result"
	"github.com/Voskan/codexsentinel/config"
	"github.com/Voskan/codexsentinel/internal/lsp"
	"github.com/Voskan/codexsentinel/internal/mcp"
	"github.com/Voskan/codexsentinel/internal/version"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// The lsp and mcp commands speak JSON-RPC on stdout, so nothing else may be
// written there: logs go to stderr (warnings only) or to --log-file.

// NewLSPCmd returns the `lsp` command, a Language Server Protocol server on
// stdio.
func NewLSPCmd() *cobra.Command {
	var logFile string
	var debounce time.Duration
	cmd := &cobra.Command{
		Use:   "lsp",
		Short: "Run a Language Server Protocol server on stdio",
		Long: `Run a Language Server Protocol server on stdin/stdout. Editors receive
findings as diagnostics when a Go file is opened or saved, with CWE, OWASP
and data flow in the message, and code actions that apply a fix or add a
suppression comment. Findings of the package-level rules for the saved file's
packages are published first; the complete findings, including taint
tracking and architecture checks, replace them when the analysis finishes.
The configuration is read from the workspace root.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			logger, logOut, closeLog, err := serverLogger(logFile)
			if err != nil {
				return err
			}
			defer closeLog()
			srv := &lsp.Server{
				Analyze: func(ctx context.Context, req lsp.Request) ([]result.Issue, error) {
					cfg, err := configForTarget(req.Root)
					if err != nil {
						return nil, err
					}
					opts := engine.Options{Focus: req.Files, Early: req.Early}
					return runAnalysis(ctx, req.Root, "", cfg, "", logger, opts)
				},
				SuppressionsForbidden: func(root string) bool {
					cfg, err := configForTarget(root)
					return err == nil && cfg.Suppression.ForbidNewSuppressions
				},
				Log: logOut, Debounce: debounce,
			}
			return srv.Serve(cmd.Context(), os.Stdin, os.Stdout)
		},
	}
	cmd.Flags().StringVar(&logFile, "log-file", "", "Write server logs to this file instead of warnings to stderr")
	cmd.Flags().DurationVar(&debounce, "debounce", 200*time.Millisecond, "Wait this long after a save before analyzing")
	return cmd
}

// NewMCPCmd returns the `mcp` command, a Model Context Protocol server on
// stdio.
func NewMCPCmd() *cobra.Command {
	var logFile string
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Run a Model Context Protocol server on stdio",
		Long: `Run a Model Context Protocol server (JSON-RPC 2.0, one message per line) on
stdin/stdout with the tools scan_path, scan_diff, verify_capabilities,
explain_rule and list_rules. Analyses run locally; the dependency audit
queries vulnerability databases only when it is enabled in the configuration.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			logger, logOut, closeLog, err := serverLogger(logFile)
			if err != nil {
				return err
			}
			defer closeLog()
			srv := &mcp.Server{Backend: mcpBackend{logger: logger}, Version: version.Version, Log: logOut}
			return srv.Serve(cmd.Context(), os.Stdin, os.Stdout)
		},
	}
	cmd.Flags().StringVar(&logFile, "log-file", "", "Write server logs to this file instead of warnings to stderr")
	return cmd
}

// serverLogger returns a logger that never writes to stdout, together with a
// writer for the server's own messages.
func serverLogger(logFile string) (*zap.SugaredLogger, io.Writer, func(), error) {
	var out zapcore.WriteSyncer = zapcore.Lock(os.Stderr)
	level := zapcore.WarnLevel
	closeFn := func() {}
	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("open log file: %w", err)
		}
		out, level = zapcore.Lock(f), zapcore.InfoLevel
		closeFn = func() { _ = f.Close() }
	}
	enc := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	logger := zap.New(zapcore.NewCore(enc, out, level)).Sugar()
	var logOut io.Writer = os.Stderr
	if logFile != "" {
		logOut = out
	}
	return logger, logOut, closeFn, nil
}

// configForTarget loads the configuration of the project containing target
// (see loadTargetConfig), or the defaults when it has none. The servers do
// not fall back to their working directory, which editors choose freely.
func configForTarget(target string) (*config.Config, error) {
	loaded, err := loadTargetConfig(target, "", false)
	if err != nil {
		return nil, err
	}
	return loaded.Config, nil
}

// mcpBackend runs the same analyses as the scan and caps commands.
type mcpBackend struct{ logger *zap.SugaredLogger }

func (b mcpBackend) Scan(ctx context.Context, req mcp.ScanRequest) ([]result.Issue, error) {
	target := normalizeTargetPath(req.Path)
	if _, err := os.Stat(target); err != nil {
		return nil, err
	}
	cfg, err := configForTarget(target)
	if err != nil {
		return nil, err
	}
	var issues []result.Issue
	if req.DepsOnly {
		issues, err = runDependencyAnalysis(ctx, target, cfg, b.logger)
	} else {
		issues, err = runFullAnalysis(ctx, target, "", cfg, req.Severity, b.logger)
	}
	if err != nil || req.GitRef == "" {
		return issues, err
	}
	opts := scanOptions{diffRef: req.GitRef, forbidSuppressions: req.ForbidNewSuppressions}
	if issues, err = applyBaselineAndDiff(ctx, target, opts, issues, b.logger); err != nil {
		return nil, err
	}
	guard, err := checkNewSuppressions(ctx, target, opts, cfg, b.logger)
	return append(guard, issues...), err
}

func (b mcpBackend) VerifyCapabilities(ctx context.Context, path, lockfile string) (string, []result.Issue, error) {
	return verifyCapabilities(ctx, normalizeTargetPath(path), "", lockfile)
}
