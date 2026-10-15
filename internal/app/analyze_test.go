package app

import (
	"os"
	"path/filepath"
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
