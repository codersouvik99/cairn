// Package app wires CAIRN's parsers, deterministic rules, and report model
// together. It owns the case-directory boundary; the lower-level analyzers do
// not read files or make network calls.
package app

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/codersouvik99/cairn/internal/compose"
	"github.com/codersouvik99/cairn/internal/core"
	"github.com/codersouvik99/cairn/internal/report"
)

const defaultMaxFileBytes = 8 * 1024 * 1024

var authCandidates = []string{
	"auth.log",
	"secure",
	"sudo.log",
	"syslog",
	"messages",
}

var composeCandidates = []string{
	"compose.yml",
	"compose.yaml",
	"docker-compose.yml",
	"docker-compose.yaml",
}

// Options controls one offline case analysis.
type Options struct {
	CaseDir      string
	Year         int
	Timezone     *time.Location
	MaxFileBytes int64
}

// AnalyzeCase reads only known case files, applies the deterministic rules,
// and returns a complete report model. Missing optional sources become
// warnings; malformed sources do not stop other sources from being analyzed.
func AnalyzeCase(options Options) (report.Data, error) {
	root, err := secureCaseRoot(options.CaseDir)
	if err != nil {
		return report.Data{}, err
	}
	maxBytes := options.MaxFileBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxFileBytes
	}
	location := options.Timezone
	if location == nil {
		location = time.UTC
	}
	metadata := core.CaseMetadata{Year: options.Year, Location: location}

	var sources []report.Source
	var events []core.Event
	var warnings []report.Warning
	readAuthCount := 0
	for _, name := range authCandidates {
		data, found, source, readErr := readKnownFile(root, name, "authentication", maxBytes)
		if readErr != nil {
			warnings = append(warnings, report.Warning{Kind: "input", SourceFile: name, Message: readErr.Error()})
			continue
		}
		if !found {
			continue
		}
		readAuthCount++
		sources = append(sources, source)
		parsed := core.Parse(data, name, metadata)
		events = append(events, parsed.Events...)
		warnings = append(warnings, coreWarnings(parsed.Warnings)...)
	}
	if readAuthCount == 0 {
		warnings = append(warnings, report.Warning{Kind: "input", Message: "no supported Linux authentication log was found in the case directory"})
	}

	var composeFindings []compose.Finding
	readComposeCount := 0
	for _, name := range composeCandidates {
		data, found, source, readErr := readKnownFile(root, name, "docker compose", maxBytes)
		if readErr != nil {
			warnings = append(warnings, report.Warning{Kind: "input", SourceFile: name, Message: readErr.Error()})
			continue
		}
		if !found {
			continue
		}
		readComposeCount++
		sources = append(sources, source)
		findings, auditErr := compose.Audit(data, name)
		if auditErr != nil {
			warnings = append(warnings, report.Warning{Kind: "compose", SourceFile: name, Message: auditErr.Error()})
			continue
		}
		composeFindings = append(composeFindings, findings...)
	}
	if readComposeCount == 0 {
		warnings = append(warnings, report.Warning{Kind: "input", Message: "no supported Docker Compose file was found in the case directory"})
	}

	parsed := core.ParseResult{Events: events}
	for _, warning := range warnings {
		if warning.Kind == "input" || warning.Kind == "compose" {
			continue
		}
		parsed.Warnings = append(parsed.Warnings, core.Warning{
			Kind:       core.WarningKind(warning.Kind),
			Message:    warning.Message,
			SourceFile: warning.SourceFile,
			Filename:   warning.SourceFile,
			LineNumber: warning.Line,
			Line:       warning.Line,
		})
	}
	analysis := core.AnalyzeParsed(parsed)

	// AnalyzeParsed returns the same parser warnings already represented above.
	// Build the final warning slice from the original order to retain the exact
	// source context and add only input/Compose warnings here.
	finalWarnings := append([]report.Warning(nil), warnings...)
	for _, warning := range analysis.Warnings {
		if !containsWarning(finalWarnings, warning) {
			finalWarnings = append(finalWarnings, report.Warning{
				Kind:       string(warning.Kind),
				SourceFile: warning.SourceFile,
				Line:       warning.LineNumber,
				Message:    warning.Message,
			})
		}
	}
	report.SortWarnings(finalWarnings)

	return report.NewData(sources, analysis, composeFindings, finalWarnings), nil
}

func secureCaseRoot(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("case directory is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve case directory: %w", err)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", fmt.Errorf("case directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("case path is not a regular directory: %s", path)
	}
	return abs, nil
}

func readKnownFile(root, name, kind string, maxBytes int64) ([]byte, bool, report.Source, error) {
	clean := filepath.Clean(name)
	if clean != name || filepath.IsAbs(name) || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean == ".." {
		return nil, false, report.Source{}, fmt.Errorf("unsafe case filename %q", name)
	}
	path := filepath.Join(root, clean)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, false, report.Source{}, nil
	}
	if err != nil {
		return nil, false, report.Source{}, fmt.Errorf("inspect %s: %w", name, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, false, report.Source{}, fmt.Errorf("refusing symlink input %s", name)
	}
	if !info.Mode().IsRegular() {
		return nil, false, report.Source{}, fmt.Errorf("refusing non-regular input %s", name)
	}
	file, err := openInputNoFollow(path)
	if err != nil {
		if errors.Is(err, errNoFollowSymlink) {
			return nil, false, report.Source{}, fmt.Errorf("refusing symlink input %s", name)
		}
		return nil, false, report.Source{}, fmt.Errorf("open %s: %w", name, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, false, report.Source{}, fmt.Errorf("read %s: %w", name, err)
	}
	if int64(len(data)) > maxBytes {
		return nil, false, report.Source{}, fmt.Errorf("input %s exceeds the %d-byte limit", name, maxBytes)
	}
	return data, true, report.Source{Name: filepath.ToSlash(name), Kind: kind, Bytes: len(data), SHA256: report.Hash(data)}, nil
}

func coreWarnings(warnings []core.Warning) []report.Warning {
	result := make([]report.Warning, 0, len(warnings))
	for _, warning := range warnings {
		result = append(result, report.Warning{
			Kind:       string(warning.Kind),
			SourceFile: warning.SourceFile,
			Line:       warning.LineNumber,
			Message:    warning.Message,
		})
	}
	return result
}

func containsWarning(warnings []report.Warning, warning core.Warning) bool {
	for _, current := range warnings {
		if current.Kind == string(warning.Kind) && current.SourceFile == warning.SourceFile &&
			current.Line == warning.LineNumber && current.Message == warning.Message {
			return true
		}
	}
	return false
}
