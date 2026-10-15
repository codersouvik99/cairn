package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunAnalyzeRefusesEvidenceOutput(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "auth.log")
	want := []byte("evidence must remain intact")
	if err := os.WriteFile(input, want, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	err := runAnalyze([]string{"--case-dir", directory, "--output", input})
	if err == nil || !strings.Contains(err.Error(), "supported input evidence") {
		t.Fatalf("runAnalyze() error = %v, want supported evidence error", err)
	}
	got, readErr := os.ReadFile(input)
	if readErr != nil {
		t.Fatalf("ReadFile() error = %v", readErr)
	}
	if string(got) != string(want) {
		t.Fatalf("input changed to %q", got)
	}
}
