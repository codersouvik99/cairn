// Package demo provides the fixed, harmless incident case used by the CLI,
// integration tests, and the project walkthrough.
package demo

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed testdata/auth.log testdata/compose.yml
var caseFiles embed.FS

var files = []string{"auth.log", "compose.yml"}

// Generate writes the deterministic synthetic case to destination. Existing
// directories are protected unless force is explicitly requested.
func Generate(destination string, force bool) error {
	if destination == "" {
		return fmt.Errorf("demo destination is required")
	}
	info, err := os.Stat(destination)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("demo destination is not a directory: %s", destination)
		}
		if !force {
			entries, readErr := os.ReadDir(destination)
			if readErr != nil {
				return fmt.Errorf("inspect demo destination: %w", readErr)
			}
			if len(entries) != 0 {
				return fmt.Errorf("demo destination is not empty; use --force to replace its files")
			}
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect demo destination: %w", err)
	}
	if err := os.MkdirAll(destination, 0o755); err != nil {
		return fmt.Errorf("create demo destination: %w", err)
	}
	for _, name := range files {
		data, readErr := fs.ReadFile(caseFiles, "testdata/"+name)
		if readErr != nil {
			return fmt.Errorf("read embedded demo %s: %w", name, readErr)
		}
		path := filepath.Join(destination, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return fmt.Errorf("write demo %s: %w", name, err)
		}
	}
	return nil
}
