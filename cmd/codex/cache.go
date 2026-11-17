package codex

import (
	"fmt"

	"github.com/Voskan/codexsentinel/v2/analyzer/cache"
	"github.com/Voskan/codexsentinel/v2/config"
	"github.com/spf13/cobra"
)

// NewCacheCmd returns the `cache` command that reports on and clears the
// analysis cache.
func NewCacheCmd() *cobra.Command {
	var configFile string
	cmd := &cobra.Command{
		Use:   "cache",
		Short: "Show or clear the analysis cache",
	}
	cmd.PersistentFlags().StringVar(&configFile, "config", "", "Path to a custom config file")

	status := &cobra.Command{
		Use:   "status",
		Short: "Show the cache directory, its entries and their size",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, enabled, err := cacheDir(configFile)
			if err != nil {
				return err
			}
			entries, size, err := cache.Usage(dir)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Directory: %s\n", dir)
			fmt.Fprintf(out, "Enabled:   %t\n", enabled)
			fmt.Fprintf(out, "Entries:   %d\n", entries)
			fmt.Fprintf(out, "Size:      %s\n", humanBytes(size))
			return nil
		},
	}
	clean := &cobra.Command{
		Use:   "clean",
		Short: "Remove every cache entry",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, _, err := cacheDir(configFile)
			if err != nil {
				return err
			}
			removed, err := cache.Clean(dir)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Removed %d cache entries from %s\n", removed, dir)
			return nil
		},
	}
	cmd.AddCommand(status, clean)
	return cmd
}

// cacheDir resolves the cache directory from the configuration.
func cacheDir(configFile string) (string, bool, error) {
	var cfg *config.Config
	var err error
	if configFile != "" {
		cfg, err = config.LoadFromPath(configFile)
	} else {
		cfg, err = config.LoadDefaultPathPtr()
	}
	if err != nil {
		return "", false, err
	}
	dir, err := cache.ResolveDir(cfg.Scan.CacheDir)
	return dir, cfg.Scan.EnableCache, err
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
