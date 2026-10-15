package report

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/frontier-buildathon/cairn/internal/compose"
	"github.com/frontier-buildathon/cairn/internal/core"
)

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"formatTime":       FormatTime,
	"eventLabel":       eventLabel,
	"ruleLabel":        ruleLabel,
	"severityClass":    severityClass,
	"findingLocation":  findingLocation,
	"composeLocation":  composeLocation,
	"evidenceLocation": evidenceLocation,
	"sourceLocation":   sourceLocation,
	"join":             strings.Join,
}).Parse(reportHTML))

// RenderHTML renders a complete, self-contained HTML document.
func RenderHTML(data Data) ([]byte, error) {
	var buffer bytes.Buffer
	if err := htmlTemplate.Execute(&buffer, data); err != nil {
		return nil, fmt.Errorf("render report: %w", err)
	}
	return buffer.Bytes(), nil
}

// WriteHTML creates the parent directory and writes one report file. The
// output path is controlled by the caller, while report contents remain fully
// escaped by html/template.
func WriteHTML(path string, data Data) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("report output path is empty")
	}
	content, err := RenderHTML(data)
	if err != nil {
		return err
	}
	parent := filepath.Dir(path)
	if parent != "." && parent != "" {
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return fmt.Errorf("create report directory: %w", err)
		}
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create report: %w", err)
	}
	defer file.Close()
	if _, err := file.Write(content); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return file.Close()
}

func eventLabel(event core.Event) string {
	switch event.Kind {
	case core.EventFailedPassword:
		return "SSH authentication failure"
	case core.EventInvalidUser:
		return "SSH invalid-user attempt"
	case core.EventAcceptedLogin:
		return "Successful SSH login"
	case core.EventSudo, core.EventSudoToRoot:
		return "Sudo activity"
	case core.EventRootSession:
		return "Root session opened"
	default:
		return string(event.Kind)
	}
}

func ruleLabel(rule core.RuleID) string {
	switch rule {
	case core.RuleBruteForce:
		return "Repeated SSH failures"
	case core.RuleSuccessAfterFailures:
		return "Successful login after failures"
	case core.RulePrivilegeEscalation:
		return "Potential privilege escalation"
	default:
		return string(rule)
	}
}

func severityClass(value interface{}) string {
	severity := fmt.Sprint(value)
	switch strings.ToLower(severity) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "neutral"
	}
}

func findingLocation(finding core.Finding) string {
	if finding.SourceFile == "" {
		return "unknown source"
	}
	return fmt.Sprintf("%s:%d", finding.SourceFile, finding.LineNumber)
}

func composeLocation(finding compose.Finding) string {
	if finding.SourceFile == "" {
		return "unknown source"
	}
	if finding.Line <= 0 {
		return finding.SourceFile
	}
	return fmt.Sprintf("%s:%d:%d", finding.SourceFile, finding.Line, finding.Column)
}

func evidenceLocation(event core.Event) string {
	if event.SourceFile == "" {
		return "unknown source"
	}
	return fmt.Sprintf("%s:%d", event.SourceFile, event.LineNumber)
}

func sourceLocation(reference core.SourceReference) string {
	filename := reference.SourceFile
	if filename == "" {
		filename = reference.Filename
	}
	line := reference.LineNumber
	if line == 0 {
		line = reference.Line
	}
	if filename == "" {
		return "unknown source"
	}
	return fmt.Sprintf("%s:%d", filename, line)
}

// Keep the renderer's writer shape visible to package users and make it easy
// to use in a test without creating a file.
func renderTo(w io.Writer, data Data) error {
	return htmlTemplate.Execute(w, data)
}
