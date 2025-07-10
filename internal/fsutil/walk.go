// Package fsutil provides safe and configurable filesystem traversal.
package fsutil

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// WalkOptions defines parameters for walking the file tree.
type WalkOptions struct {
	RootDir            string   // root path to start scanning from
	ExcludedPaths      []string // relative paths to exclude (subdirs or globs)
	AllowedExtensions  []string // file extensions to include (e.g. .go)
	MaxFileSizeBytes   int64    // maximum allowed file size in bytes
	FollowSymlinks     bool     // whether to follow symbolic links
	IncludeHiddenFiles bool     // whether to include dotfiles
}

// FileInfo represents a file to be analyzed.
type FileInfo struct {
	Path string // absolute file path
	Size int64  // size in bytes
}

// Walk recursively walks the filesystem and returns files that match the options.
func Walk(opts WalkOptions) ([]FileInfo, error) {
	var result []FileInfo

	skipPaths := make(map[string]struct{})
	for _, ex := range opts.ExcludedPaths {
		skipPaths[filepath.Clean(ex)] = struct{}{}
	}

	err := filepath.WalkDir(opts.RootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // ignore inaccessible paths
		}

		relPath, _ := filepath.Rel(opts.RootDir, path)
		relPath = filepath.ToSlash(relPath)

		// Skip hidden files/dirs if disabled
		if !opts.IncludeHiddenFiles && isHidden(relPath) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip excluded paths
		for skip := range skipPaths {
			if strings.HasPrefix(relPath, skip) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}

		// Skip directories
		if d.IsDir() {
			return nil
		}

		// Extension check
		if len(opts.AllowedExtensions) > 0 && !hasAllowedExt(d.Name(), opts.AllowedExtensions) {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}

		// Size check
		if opts.MaxFileSizeBytes > 0 && info.Size() > opts.MaxFileSizeBytes {
			return nil
		}

		// Symlink check
		if !opts.FollowSymlinks && isSymlink(info) {
			return nil
		}

		result = append(result, FileInfo{
			Path: path,
			Size: info.Size(),
		})

		return nil
	})

	if err != nil {
		return nil, err
	}

	return result, nil
}

// hasAllowedExt returns true if the filename ends with one of the given extensions.
func hasAllowedExt(name string, exts []string) bool {
	lower := strings.ToLower(name)
	for _, ext := range exts {
		if strings.HasSuffix(lower, strings.ToLower(ext)) {
			return true
		}
	}
	return false
}

// isSymlink checks if the file is a symlink.
func isSymlink(info fs.FileInfo) bool {
	return info.Mode()&os.ModeSymlink != 0
}

// isHidden determines whether the path is hidden (starts with dot).
func isHidden(path string) bool {
	parts := strings.Split(path, string(filepath.Separator))
	for _, p := range parts {
		if strings.HasPrefix(p, ".") {
			return true
		}
	}
	return false
}
