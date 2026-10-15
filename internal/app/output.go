package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ValidateReportOutput rejects report destinations that could overwrite case
// evidence. It compares cleaned and symlink-resolved paths, and also rejects
// an existing output symlink before report.WriteHTML can follow it.
func ValidateReportOutput(caseDir, output string) error {
	if strings.TrimSpace(output) == "" {
		return fmt.Errorf("report output path is empty")
	}
	root, err := secureCaseRoot(caseDir)
	if err != nil {
		return err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("resolve case directory: %w", err)
	}

	outputPath, err := filepath.Abs(output)
	if err != nil {
		return fmt.Errorf("resolve report output: %w", err)
	}
	outputPath = filepath.Clean(outputPath)
	if info, lstatErr := os.Lstat(outputPath); lstatErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing report output %q: existing output path is a symlink", output)
		}
	} else if !os.IsNotExist(lstatErr) {
		return fmt.Errorf("inspect report output: %w", lstatErr)
	}

	resolvedOutput, err := resolveOutputPath(outputPath)
	if err != nil {
		return fmt.Errorf("resolve report output: %w", err)
	}
	for _, name := range append(append([]string(nil), authCandidates...), composeCandidates...) {
		evidencePath := filepath.Clean(filepath.Join(root, name))
		if resolvedOutput == evidencePath || outputPath == evidencePath {
			return fmt.Errorf("refusing report output %q: it names supported input evidence %q", output, name)
		}

		if info, statErr := os.Stat(evidencePath); statErr == nil {
			if outputInfo, outputStatErr := os.Stat(outputPath); outputStatErr == nil && os.SameFile(info, outputInfo) {
				return fmt.Errorf("refusing report output %q: it refers to supported input evidence %q", output, name)
			}
		} else if !os.IsNotExist(statErr) {
			return fmt.Errorf("inspect supported input %q: %w", name, statErr)
		}
	}
	return nil
}

// resolveOutputPath resolves all existing parent components while preserving
// not-yet-created report components, so a symlinked case-directory alias is
// equivalent to its real path even when the report itself does not exist yet.
func resolveOutputPath(path string) (string, error) {
	path = filepath.Clean(path)
	missing := make([]string, 0, 2)
	existing := path
	for {
		if _, err := os.Lstat(existing); err == nil {
			resolved, err := filepath.EvalSymlinks(existing)
			if err != nil {
				return "", err
			}
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return filepath.Clean(resolved), nil
		} else if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return path, nil
		}
		missing = append(missing, filepath.Base(existing))
		existing = parent
	}
}
