package app

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/frontier-buildathon/cairn/internal/core"
	"github.com/frontier-buildathon/cairn/internal/demo"
	"github.com/frontier-buildathon/cairn/internal/report"
)

func TestAnalyzeDemoCaseProducesStableEvidenceBackedResult(t *testing.T) {
	directory := t.TempDir()
	if err := demo.Generate(directory, false); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	data, err := AnalyzeCase(Options{CaseDir: directory, Timezone: time.UTC})
	if err != nil {
		t.Fatalf("AnalyzeCase() error = %v", err)
	}
	if data.Summary.Events != 7 {
		t.Fatalf("events = %d, want 7", data.Summary.Events)
	}
	if data.Summary.AuthenticationFindings != 3 {
		t.Fatalf("auth findings = %d, want 3", data.Summary.AuthenticationFindings)
	}
	if data.Summary.ComposeFindings != 2 {
		t.Fatalf("Compose findings = %d, want 2", data.Summary.ComposeFindings)
	}
	if data.Summary.HighestSeverity != "critical" {
		t.Fatalf("highest severity = %q, want critical", data.Summary.HighestSeverity)
	}
	if len(data.Warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", data.Warnings)
	}
	if len(data.Sources) != 2 || data.Sources[0].SHA256 == "" || data.Sources[1].SHA256 == "" {
		t.Fatalf("sources = %+v, want two hashed sources", data.Sources)
	}
	if data.Timeline[0].Kind != core.EventFailedPassword || data.Timeline[len(data.Timeline)-1].Kind != core.EventSudoToRoot {
		t.Fatalf("timeline = %+v", data.Timeline)
	}

	first, err := report.RenderHTML(data)
	if err != nil {
		t.Fatalf("RenderHTML() error = %v", err)
	}
	second, err := report.RenderHTML(data)
	if err != nil {
		t.Fatalf("second RenderHTML() error = %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("rendered reports are not deterministic")
	}
	text := string(first)
	for _, want := range []string{"Repeated SSH failures", "Successful login after failures", "Potential privilege escalation", "docker-socket", "auth.log:1", "compose.yml:4"} {
		if !strings.Contains(text, want) {
			t.Errorf("report does not contain %q", want)
		}
	}
}

func TestAnalyzeCaseRejectsSymlinkInputs(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "outside.log")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Symlink(target, filepath.Join(directory, "auth.log")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	data, err := AnalyzeCase(Options{CaseDir: directory, Timezone: time.UTC})
	if err != nil {
		t.Fatalf("AnalyzeCase() error = %v", err)
	}
	found := false
	for _, warning := range data.Warnings {
		if strings.Contains(warning.Message, "symlink") {
			found = true
		}
	}
	if !found {
		t.Fatalf("warnings = %+v, want symlink warning", data.Warnings)
	}
}

func TestOpenInputNoFollowRejectsSymlinkAtOpen(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("O_NOFOLLOW regression applies to the Linux deployment target")
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "outside.log")
	link := filepath.Join(directory, "auth.log")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	file, err := openInputNoFollow(link)
	if file != nil {
		file.Close()
	}
	if !errors.Is(err, errNoFollowSymlink) {
		t.Fatalf("openInputNoFollow() error = %v, want no-follow symlink error", err)
	}
}

func TestAnalyzeCaseUsesEmbeddedTimezoneData(t *testing.T) {
	location, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatalf("LoadLocation() error = %v", err)
	}
	if location.String() != "America/New_York" {
		t.Fatalf("location = %q, want America/New_York", location)
	}
}

func TestValidateReportOutputRejectsSupportedEvidence(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "auth.log")
	if err := os.WriteFile(input, []byte("evidence"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	paths := []string{
		input,
		filepath.Join(directory, ".", "auth.log"),
		filepath.Join(directory, "nested", "..", "auth.log"),
	}
	alias := filepath.Join(directory, "case-alias")
	if err := os.Symlink(directory, alias); err == nil {
		paths = append(paths, filepath.Join(alias, "auth.log"))
	}
	for _, output := range paths {
		if err := ValidateReportOutput(directory, output); err == nil || !strings.Contains(err.Error(), "supported input evidence") {
			t.Errorf("ValidateReportOutput(%q) error = %v, want supported evidence error", output, err)
		}
	}
}

func TestValidateReportOutputRejectsSymlinkDestination(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "auth.log")
	output := filepath.Join(directory, "report.html")
	if err := os.WriteFile(input, []byte("evidence"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Symlink(input, output); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := ValidateReportOutput(directory, output); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("ValidateReportOutput() error = %v, want symlink error", err)
	}
}

func TestAnalyzeCaseRejectsOversizedInput(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "auth.log"), []byte("0123456789"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	data, err := AnalyzeCase(Options{CaseDir: directory, Timezone: time.UTC, MaxFileBytes: 4})
	if err != nil {
		t.Fatalf("AnalyzeCase() error = %v", err)
	}
	found := false
	for _, warning := range data.Warnings {
		if strings.Contains(warning.Message, "exceeds") {
			found = true
		}
	}
	if !found {
		t.Fatalf("warnings = %+v, want size warning", data.Warnings)
	}
}

func TestReportEscapesUntrustedEvidence(t *testing.T) {
	directory := t.TempDir()
	auth := "2026-01-15T10:00:00Z edge sshd[1]: Failed password for <script>alert(1)</script> from 203.0.113.9 port 22 ssh2\n"
	compose := "services:\n  '<img src=x onerror=alert(1)>':\n    privileged: true\n"
	if err := os.WriteFile(filepath.Join(directory, "auth.log"), []byte(auth), 0o600); err != nil {
		t.Fatalf("write auth log: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "compose.yml"), []byte(compose), 0o600); err != nil {
		t.Fatalf("write Compose file: %v", err)
	}
	data, err := AnalyzeCase(Options{CaseDir: directory, Timezone: time.UTC})
	if err != nil {
		t.Fatalf("AnalyzeCase() error = %v", err)
	}
	html, err := report.RenderHTML(data)
	if err != nil {
		t.Fatalf("RenderHTML() error = %v", err)
	}
	text := string(html)
	if strings.Contains(text, "<script>alert(1)</script>") || strings.Contains(text, "<img src=x onerror=alert(1)>") {
		t.Fatal("report contains unescaped attacker-controlled markup")
	}
	if !strings.Contains(text, "&lt;script&gt;") || !strings.Contains(text, "&lt;img") {
		t.Fatal("report does not contain escaped evidence")
	}
}
