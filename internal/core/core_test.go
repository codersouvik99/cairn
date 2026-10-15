package core

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

var testMetadata = CaseMetadata{Year: 2024, Location: time.UTC}

func TestParseCommonLinuxAuthRecords(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		wantKind   EventKind
		wantUser   string
		wantTarget string
		wantIP     string
		wantMethod string
		wantCmd    string
	}{
		{
			name:       "failed password",
			line:       "Jan 10 12:34:56 gateway sshd[123]: Failed password for alice from 203.0.113.5 port 54321 ssh2",
			wantKind:   EventFailedPassword,
			wantUser:   "alice",
			wantIP:     "203.0.113.5",
			wantMethod: "password",
		},
		{
			name:     "invalid user",
			line:     "Jan 10 12:35:56 gateway sshd[123]: Invalid user nobody from 203.0.113.9 port 54321",
			wantKind: EventInvalidUser,
			wantUser: "nobody",
			wantIP:   "203.0.113.9",
		},
		{
			name:       "accepted public key",
			line:       "Jan 10 12:36:56 gateway sshd[123]: Accepted publickey for alice from 203.0.113.5 port 54321 ssh2",
			wantKind:   EventAcceptedLogin,
			wantUser:   "alice",
			wantIP:     "203.0.113.5",
			wantMethod: "publickey",
		},
		{
			name:       "sudo command",
			line:       "Jan 10 12:37:56 gateway sudo[222]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash",
			wantKind:   EventSudoToRoot,
			wantUser:   "alice",
			wantTarget: "root",
			wantCmd:    "/bin/bash",
		},
		{
			name:       "sudo command to non-root user",
			line:       "Jan 10 12:37:57 gateway sudo[222]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=deploy ; COMMAND=/usr/bin/id",
			wantKind:   EventSudo,
			wantUser:   "alice",
			wantTarget: "deploy",
			wantCmd:    "/usr/bin/id",
		},
		{
			name:       "sudo session",
			line:       "Jan 10 12:38:56 gateway sudo[222]: pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)",
			wantKind:   EventSudoToRoot,
			wantUser:   "alice",
			wantTarget: "root",
		},
		{
			name:       "root session",
			line:       "Jan 10 12:39:56 gateway sshd[123]: pam_unix(sshd:session): session opened for user root(uid=0) by alice(uid=1000)",
			wantKind:   EventRootSession,
			wantUser:   "alice",
			wantTarget: "root",
		},
		{
			name:       "su to root",
			line:       "Jan 10 12:40:56 gateway su[222]: (to root) alice on /dev/pts/0",
			wantKind:   EventSudoToRoot,
			wantUser:   "alice",
			wantTarget: "root",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseLine("auth.log", 7, tt.line, testMetadata)
			if len(result.Warnings) != 0 {
				t.Fatalf("unexpected warnings: %+v", result.Warnings)
			}
			if result.Event == nil {
				t.Fatal("expected event")
			}
			event := *result.Event
			if event.Kind != tt.wantKind || event.User != tt.wantUser || event.TargetUser != tt.wantTarget ||
				event.SourceIP != tt.wantIP || event.AuthMethod != tt.wantMethod || event.Command != tt.wantCmd {
				t.Fatalf("event = %+v", event)
			}
			wantTime := time.Date(2024, time.January, 10, 12, 34, 56, 0, time.UTC)
			if event.Timestamp.IsZero() || event.Timestamp.Location() != time.UTC {
				t.Fatalf("timestamp was not normalized: %v", event.Timestamp)
			}
			if event.SourceFile != "auth.log" || event.Filename != "auth.log" || event.LineNumber != 7 || event.Line != 7 {
				t.Fatalf("source location was not retained: %+v", event)
			}
			if tt.name == "failed password" && !event.Timestamp.Equal(wantTime) {
				t.Fatalf("timestamp = %v, want %v", event.Timestamp, wantTime)
			}
		})
	}
}

func TestParseReaderRetainsSourceLines(t *testing.T) {
	input := strings.Join([]string{
		"# unrelated comment",
		"Jan 10 12:34:56 gateway sshd[1]: Failed password for alice from 192.0.2.10 port 22 ssh2",
		"",
		"Jan 10 12:35:56 gateway sshd[1]: Accepted password for alice from 192.0.2.10 port 22 ssh2",
	}, "\n")
	result := ParseAuthLog(strings.NewReader(input), "/evidence/auth.log", testMetadata)
	if len(result.Events) != 2 {
		t.Fatalf("events = %d, want 2; warnings = %+v", len(result.Events), result.Warnings)
	}
	if result.Events[0].LineNumber != 2 || result.Events[1].LineNumber != 4 {
		t.Fatalf("line numbers = %d, %d", result.Events[0].LineNumber, result.Events[1].LineNumber)
	}
	if len(result.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %+v", result.Warnings)
	}
}

func TestMalformedAndAmbiguousLinesWarnWithoutPanic(t *testing.T) {
	tests := []struct {
		name         string
		line         string
		metadata     CaseMetadata
		wantEvent    bool
		wantZeroTime bool
		wantWarning  WarningKind
	}{
		{
			name:         "missing timestamp",
			line:         "sshd: Failed password for alice from 192.0.2.1 port 22 ssh2",
			wantEvent:    true,
			wantZeroTime: true,
			wantWarning:  WarningMalformed,
		},
		{
			name:         "year is ambiguous",
			line:         "Jan 10 12:34:56 gateway sshd[1]: Failed password for alice from 192.0.2.1 port 22 ssh2",
			metadata:     CaseMetadata{Location: time.UTC},
			wantEvent:    true,
			wantZeroTime: true,
			wantWarning:  WarningAmbiguousTimestamp,
		},
		{
			name:         "invalid date",
			line:         "Jan 32 12:34:56 gateway sshd[1]: Failed password for alice from 192.0.2.1 port 22 ssh2",
			metadata:     testMetadata,
			wantEvent:    true,
			wantZeroTime: true,
			wantWarning:  WarningMalformed,
		},
		{
			name:        "unsupported authentication-looking line",
			line:        "Jan 10 12:34:56 gateway sshd[1]: Connection closed by 192.0.2.1 [preauth]",
			metadata:    testMetadata,
			wantWarning: WarningUnrecognized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseLine("broken.log", 3, tt.line, tt.metadata)
			if (result.Event != nil) != tt.wantEvent {
				t.Fatalf("event present = %v, want %v; result = %+v", result.Event != nil, tt.wantEvent, result)
			}
			if result.Event != nil && result.Event.Timestamp.IsZero() != tt.wantZeroTime {
				t.Fatalf("zero timestamp = %v, want %v", result.Event.Timestamp.IsZero(), tt.wantZeroTime)
			}
			if tt.wantWarning == "" {
				return
			}
			found := false
			for _, warning := range result.Warnings {
				if warning.Kind == tt.wantWarning && warning.SourceFile == "broken.log" && warning.LineNumber == 3 {
					found = true
				}
			}
			if !found {
				t.Fatalf("warnings = %+v, want kind %q", result.Warnings, tt.wantWarning)
			}
		})
	}
}

func TestTimestampNormalizationUsesCaseMetadata(t *testing.T) {
	location := time.FixedZone("case-zone", 5*60*60+30*60)
	line := "Jan 10 12:34:56 gateway sshd[1]: Accepted password for alice from 192.0.2.1 port 22 ssh2"
	result := ParseLine("auth.log", 1, line, CaseMetadata{Year: 2025, Timezone: location})
	if result.Event == nil || len(result.Warnings) != 0 {
		t.Fatalf("result = %+v", result)
	}
	want := time.Date(2025, time.January, 10, 12, 34, 56, 0, location)
	if !result.Event.Timestamp.Equal(want) || result.Event.Timestamp.Location() != location {
		t.Fatalf("timestamp = %v (%s), want %v (%s)", result.Event.Timestamp, result.Event.Timestamp.Location(), want, location)
	}

	rfc3339 := ParseLine("auth.log", 2, "2025-01-10T12:34:56-02:00 gateway sshd[1]: Accepted password for alice from 192.0.2.1 port 22 ssh2", CaseMetadata{})
	if rfc3339.Event == nil || len(rfc3339.Warnings) != 0 || rfc3339.Event.Timestamp.IsZero() {
		t.Fatalf("RFC3339 result = %+v", rfc3339)
	}
}

func TestRulesThresholdsAndSourceBoundaries(t *testing.T) {
	lines := []string{
		"Jan 10 00:00:00 gateway sshd[1]: Failed password for alice from 192.0.2.10 port 22 ssh2",
		"Jan 10 00:01:00 gateway sshd[1]: Failed password for alice from 192.0.2.10 port 22 ssh2",
		"Jan 10 00:02:00 gateway sshd[1]: Failed password for alice from 192.0.2.10 port 22 ssh2",
		"Jan 10 00:03:00 gateway sshd[1]: Invalid user bob from 192.0.2.10 port 22",
		// Exactly ten minutes from the first failure is inclusive.
		"Jan 10 00:10:00 gateway sshd[1]: Failed password for alice from 192.0.2.10 port 22 ssh2",
		// A different source must not contribute to the threshold.
		"Jan 10 00:10:00 gateway sshd[1]: Failed password for alice from 192.0.2.11 port 22 ssh2",
	}
	parsed := ParseAuthLines(lines, "auth.log", testMetadata)
	if len(parsed.Warnings) != 0 || len(parsed.Events) != len(lines) {
		t.Fatalf("parsed = %+v", parsed)
	}
	analysis := Analyze(parsed.Events)
	brute := findingsForRule(analysis.Findings, RuleBruteForce)
	if len(brute) != 1 || brute[0].SourceIP != "192.0.2.10" || brute[0].FailureCount != 5 {
		t.Fatalf("brute-force findings = %+v", brute)
	}

	outside := ParseAuthLines([]string{
		"Jan 10 00:00:00 gateway sshd[1]: Failed password for alice from 192.0.2.12 port 22 ssh2",
		"Jan 10 00:01:00 gateway sshd[1]: Failed password for alice from 192.0.2.12 port 22 ssh2",
		"Jan 10 00:02:00 gateway sshd[1]: Failed password for alice from 192.0.2.12 port 22 ssh2",
		"Jan 10 00:03:00 gateway sshd[1]: Failed password for alice from 192.0.2.12 port 22 ssh2",
		"Jan 10 00:10:01 gateway sshd[1]: Failed password for alice from 192.0.2.12 port 22 ssh2",
	}, "auth.log", testMetadata)
	if got := findingsForRule(Analyze(outside.Events).Findings, RuleBruteForce); len(got) != 0 {
		t.Fatalf("outside-window brute-force findings = %+v", got)
	}
}

func TestRulesSuccessWindowAndDifferentIP(t *testing.T) {
	tests := []struct {
		name        string
		successAt   string
		successIP   string
		wantFinding bool
	}{
		{name: "exact boundary is included", successAt: "00:15:00", successIP: "192.0.2.20", wantFinding: true},
		{name: "one second beyond boundary is excluded", successAt: "00:15:01", successIP: "192.0.2.20", wantFinding: false},
		{name: "different source is excluded", successAt: "00:15:00", successIP: "192.0.2.21", wantFinding: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := []string{
				"Jan 10 00:00:00 gateway sshd[1]: Failed password for alice from 192.0.2.20 port 22 ssh2",
				"Jan 10 " + tt.successAt + " gateway sshd[1]: Accepted password for alice from " + tt.successIP + " port 22 ssh2",
			}
			parsed := ParseAuthLines(lines, "auth.log", testMetadata)
			if len(parsed.Warnings) != 0 {
				t.Fatalf("warnings = %+v", parsed.Warnings)
			}
			findings := findingsForRule(Analyze(parsed.Events).Findings, RuleSuccessAfterFailures)
			if (len(findings) != 0) != tt.wantFinding {
				t.Fatalf("success findings = %+v, want present %v", findings, tt.wantFinding)
			}
		})
	}
}

func TestPrivilegeEscalationAfterSuccessfulLogin(t *testing.T) {
	lines := []string{
		"Jan 10 12:00:00 gateway sshd[1]: Accepted publickey for alice from 192.0.2.30 port 22 ssh2",
		"Jan 10 12:01:00 gateway sudo[2]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash",
		"Jan 10 12:02:00 gateway sshd[3]: pam_unix(sshd:session): session opened for user root(uid=0) by alice(uid=1000)",
	}
	parsed := ParseAuthLines(lines, "auth.log", testMetadata)
	if len(parsed.Warnings) != 0 || len(parsed.Events) != 3 {
		t.Fatalf("parsed = %+v", parsed)
	}
	analysis := Analyze(parsed.Events)
	findings := findingsForRule(analysis.Findings, RulePrivilegeEscalation)
	if len(findings) != 2 {
		t.Fatalf("privilege findings = %+v", findings)
	}
	if !findings[0].Explicit || findings[0].Potential || findings[0].User != "alice" {
		t.Fatalf("explicit finding = %+v", findings[0])
	}
	if findings[1].Explicit || !findings[1].Potential {
		t.Fatalf("potential finding = %+v", findings[1])
	}

	noMatch := ParseAuthLines([]string{
		"Jan 10 12:00:00 gateway sshd[1]: Accepted publickey for bob from 192.0.2.30 port 22 ssh2",
		"Jan 10 12:01:00 gateway sudo[2]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash",
	}, "auth.log", testMetadata)
	if got := findingsForRule(Analyze(noMatch.Events).Findings, RulePrivilegeEscalation); len(got) != 0 {
		t.Fatalf("unmatched escalation findings = %+v", got)
	}
}

func TestBuildTimelineIsChronologicalAndDoesNotMutateInput(t *testing.T) {
	parsed := ParseAuthLines([]string{
		"Jan 10 12:02:00 gateway sshd[1]: Accepted password for alice from 192.0.2.1 port 22 ssh2",
		"Jan 10 12:01:00 gateway sshd[1]: Failed password for alice from 192.0.2.1 port 22 ssh2",
		"sshd: Failed password for alice from 192.0.2.1 port 22 ssh2",
	}, "auth.log", testMetadata)
	original := append([]Event(nil), parsed.Events...)
	timeline := BuildTimeline(parsed.Events)
	if !reflect.DeepEqual(parsed.Events, original) {
		t.Fatal("BuildTimeline mutated input")
	}
	if timeline.Len() != 3 || timeline.Events[0].LineNumber != 2 || timeline.Events[1].LineNumber != 1 || timeline.Events[2].LineNumber != 3 {
		t.Fatalf("timeline = %+v", timeline.Events)
	}
	if _, ok := timeline.At(-1); ok {
		t.Fatal("negative timeline index unexpectedly succeeded")
	}
	if _, ok := timeline.At(3); ok {
		t.Fatal("out-of-range timeline index unexpectedly succeeded")
	}
}

func findingsForRule(findings []Finding, rule RuleID) []Finding {
	var result []Finding
	for _, finding := range findings {
		if finding.Rule == rule {
			result = append(result, finding)
		}
	}
	return result
}
