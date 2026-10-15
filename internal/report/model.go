// Package report contains CAIRN's stable report model and offline HTML
// renderer. The model deliberately keeps the original core and Compose
// evidence objects so a renderer cannot accidentally discard source context.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"

	"github.com/frontier-buildathon/cairn/internal/compose"
	"github.com/frontier-buildathon/cairn/internal/core"
)

// Source describes one file that was safely read from the case directory.
type Source struct {
	Name   string
	Kind   string
	Bytes  int
	SHA256 string
}

// Warning is a user-visible, recoverable issue encountered while importing a
// case. Warnings are deliberately separate from findings: a parser warning
// is not evidence of an attack.
type Warning struct {
	Kind       string
	SourceFile string
	Line       int
	Message    string
}

// Summary contains the small set of metrics shown at the top of the report.
type Summary struct {
	Events                 int
	FailedAuthentications  int
	SuccessfulLogins       int
	PrivilegeEvents        int
	AuthenticationFindings int
	ComposeFindings        int
	HighestSeverity        string
}

// Data is the complete deterministic report input. It contains no analysis
// start time or machine-specific path, so identical input produces identical
// output.
type Data struct {
	Title           string
	Sources         []Source
	Summary         Summary
	Timeline        []core.Event
	AuthFindings    []core.Finding
	ComposeFindings []compose.Finding
	Warnings        []Warning
}

// NewData builds the report model from the two focused analyzers.
func NewData(sources []Source, analysis core.Analysis, composeFindings []compose.Finding, warnings []Warning) Data {
	data := Data{
		Title:           "CAIRN incident triage report",
		Sources:         append([]Source(nil), sources...),
		Timeline:        append([]core.Event(nil), analysis.Timeline.Events...),
		AuthFindings:    append([]core.Finding(nil), analysis.Findings...),
		ComposeFindings: append([]compose.Finding(nil), composeFindings...),
		Warnings:        append([]Warning(nil), warnings...),
	}
	data.Summary = summarize(data.Timeline, data.AuthFindings, data.ComposeFindings)
	return data
}

func summarize(events []core.Event, authFindings []core.Finding, composeFindings []compose.Finding) Summary {
	summary := Summary{
		Events:                 len(events),
		AuthenticationFindings: len(authFindings),
		ComposeFindings:        len(composeFindings),
		HighestSeverity:        "none",
	}
	for _, event := range events {
		switch event.Kind {
		case core.EventFailedPassword, core.EventInvalidUser:
			summary.FailedAuthentications++
		case core.EventAcceptedLogin:
			summary.SuccessfulLogins++
		case core.EventSudo, core.EventSudoToRoot, core.EventRootSession:
			summary.PrivilegeEvents++
		}
	}
	for _, finding := range authFindings {
		summary.HighestSeverity = higherSeverity(summary.HighestSeverity, string(finding.Severity))
	}
	for _, finding := range composeFindings {
		summary.HighestSeverity = higherSeverity(summary.HighestSeverity, finding.Severity)
	}
	return summary
}

func higherSeverity(left, right string) string {
	weight := map[string]int{"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	if weight[right] > weight[left] {
		return right
	}
	return left
}

// Hash returns a stable SHA-256 digest for source bytes.
func Hash(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// SortWarnings gives callers a stable order when warnings originate from
// several input files.
func SortWarnings(warnings []Warning) {
	sort.SliceStable(warnings, func(i, j int) bool {
		if warnings[i].SourceFile != warnings[j].SourceFile {
			return warnings[i].SourceFile < warnings[j].SourceFile
		}
		if warnings[i].Line != warnings[j].Line {
			return warnings[i].Line < warnings[j].Line
		}
		if warnings[i].Kind != warnings[j].Kind {
			return warnings[i].Kind < warnings[j].Kind
		}
		return warnings[i].Message < warnings[j].Message
	})
}

// FormatTime is shared by the HTML template and tests. Unknown timestamps are
// rendered explicitly rather than being formatted as Go's zero date.
func FormatTime(value time.Time) string {
	if value.IsZero() {
		return "unknown time"
	}
	return value.UTC().Format(time.RFC3339)
}
