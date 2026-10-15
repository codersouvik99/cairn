// Package core contains the input-independent part of CAIRN's authentication
// analysis.  It deliberately has no filesystem or command-line dependencies so
// callers can feed it records from an auth.log file, a journal export, or a
// test fixture.
package core

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// CaseMetadata supplies the information that syslog timestamps leave out.
//
// Traditional Linux auth logs use timestamps such as "Jan 15 12:34:56" and
// omit both the year and the timezone.  Year and either Location or Timezone
// should be supplied when parsing those logs.  DefaultYear and TimezoneName
// are convenience alternatives for callers that use those names in their
// case-import configuration.  If a timezone is missing, UTC is used and a
// warning is returned; this avoids machine-local, non-reproducible results.
type CaseMetadata struct {
	Year         int
	DefaultYear  int
	Location     *time.Location
	Timezone     *time.Location
	TimezoneName string
}

// Metadata is retained as a short alias for integrations that use the more
// generic name.
type Metadata = CaseMetadata

func (m CaseMetadata) year() int {
	if m.Year != 0 {
		return m.Year
	}
	return m.DefaultYear
}

func (m CaseMetadata) location() (*time.Location, string) {
	if m.Location != nil {
		return m.Location, ""
	}
	if m.Timezone != nil {
		return m.Timezone, ""
	}
	if m.TimezoneName != "" {
		location, err := time.LoadLocation(m.TimezoneName)
		if err == nil {
			return location, ""
		}
		return time.UTC, fmt.Sprintf("cannot load timezone %q: %v; assuming UTC", m.TimezoneName, err)
	}
	return time.UTC, "timezone is not specified; assuming UTC"
}

// EventKind identifies a normalized authentication or privilege-related
// record.
type EventKind string

const (
	EventFailedPassword EventKind = "failed_password"
	EventInvalidUser    EventKind = "invalid_user"
	EventAcceptedLogin  EventKind = "accepted_login"
	EventSudo           EventKind = "sudo"
	EventSudoToRoot     EventKind = "sudo_to_root"
	EventRootSession    EventKind = "root_session"
)

// RecordKind is an alias useful to callers that call parsed lines records.
type RecordKind = EventKind

// The shorter constants make switch statements pleasant while the Event*
// names remain unambiguous in public APIs.
const (
	FailedPassword = EventFailedPassword
	InvalidUser    = EventInvalidUser
	AcceptedLogin  = EventAcceptedLogin
	Sudo           = EventSudo
	SudoToRoot     = EventSudoToRoot
	RootSession    = EventRootSession
)

// Event is a normalized record from an authentication log.  SourceFile and
// LineNumber always retain the input location supplied to the parser.  The
// Filename and Line fields mirror them for integrations that use shorter
// source-location names.
type Event struct {
	Kind      EventKind
	Timestamp time.Time
	// Time is an alias of Timestamp for consumers that use the shorter name.
	Time time.Time

	TimestampText     string
	TimestampComplete bool

	SourceFile string
	Filename   string
	LineNumber int
	Line       int
	Raw        string

	Host    string
	Process string

	// User is the login user for SSH records and the invoking user for sudo or
	// root-session records.  ActorUser is explicit for privilege records.
	User       string
	ActorUser  string
	TargetUser string
	SourceIP   string
	AuthMethod string
	Command    string

	// Message is the portion after the syslog tag.  It is useful to later
	// enrich the parser without losing the original normalized context.
	Message string

	// SourceReferences retains every source location represented by this
	// canonical event.  It is populated by DeduplicateEvents; the legacy
	// SourceFile, Filename, LineNumber, Line, and Raw fields continue to point
	// at the first source occurrence for compatibility.
	SourceReferences []SourceReference
}

// SourceReference identifies one source occurrence of an event.  Filename and
// Line mirror SourceFile and LineNumber so callers using either naming
// convention can consume deduplicated provenance without adapting the data.
type SourceReference struct {
	SourceFile string
	Filename   string
	LineNumber int
	Line       int
	Raw        string
}

// WarningKind categorizes a recoverable parser issue.
type WarningKind string

const (
	WarningMalformed          WarningKind = "malformed"
	WarningAmbiguousTimestamp WarningKind = "ambiguous_timestamp"
	WarningUnrecognized       WarningKind = "unrecognized"
	WarningInvalidMetadata    WarningKind = "invalid_metadata"
	WarningReader             WarningKind = "reader"
)

// Warning describes a problem without making parsing unsafe.  A warning is
// tied to the same source filename and 1-based line number as the record when
// one exists.
type Warning struct {
	Kind       WarningKind
	Message    string
	SourceFile string
	Filename   string
	LineNumber int
	Line       int
	Raw        string
}

// LineResult is the result of parsing one line.  Event is nil when the line
// does not contain a supported record or is too malformed to normalize.
type LineResult struct {
	Event    *Event
	Warnings []Warning
}

// ParseResult contains all supported events and recoverable warnings from a
// source.  Unrelated log lines are ignored quietly; malformed lines that look
// like authentication records are reported.
type ParseResult struct {
	Events   []Event
	Warnings []Warning
}

// Records returns the parsed events under the alternate records terminology.
func (r ParseResult) Records() []Event { return r.Events }

// Parser parses Linux auth records using fixed case metadata.
type Parser struct {
	Metadata CaseMetadata
}

// NewParser creates a parser for one case's timestamp metadata.
func NewParser(metadata CaseMetadata) Parser { return Parser{Metadata: metadata} }

// ParseLine parses one source line.  lineNumber is expected to be 1-based;
// invalid values are retained and reported rather than causing a panic.
func (p Parser) ParseLine(sourceFile string, lineNumber int, line string) LineResult {
	raw := strings.TrimRight(line, "\r\n")
	result := LineResult{}
	if lineNumber <= 0 {
		result.Warnings = append(result.Warnings, makeWarning(
			WarningMalformed, sourceFile, lineNumber, raw,
			"line number must be 1-based"))
	}
	if strings.TrimSpace(raw) == "" {
		return result
	}

	timestamp, timestampText, remainder, timestampRecognized, timestampWarnings :=
		parseTimestamp(raw, p.Metadata)
	pendingWarnings := make([]Warning, 0, len(timestampWarnings))
	if timestampWarnings != nil {
		for _, message := range timestampWarnings {
			kind := WarningAmbiguousTimestamp
			if strings.Contains(message, "cannot load timezone") {
				kind = WarningInvalidMetadata
			} else if strings.Contains(message, "invalid ") || strings.Contains(message, "unknown syslog month") {
				kind = WarningMalformed
			}
			pendingWarnings = append(pendingWarnings, makeWarning(kind, sourceFile, lineNumber, raw, message))
		}
	}
	if !timestampRecognized {
		// A malformed timestamp should not prevent us from recovering the
		// message body.  splitHeader also handles a bare auth message.
		remainder = raw
	}

	host, process, body := splitHeader(remainder)
	if body == "" {
		body = strings.TrimSpace(remainder)
	}

	event, recognized := parseBody(body, process)
	if !recognized {
		if looksLikeAuthenticationRecord(raw) {
			result.Warnings = append(result.Warnings, pendingWarnings...)
			result.Warnings = append(result.Warnings, makeWarning(
				WarningUnrecognized, sourceFile, lineNumber, raw,
				"authentication-looking line is not a supported record"))
		}
		return result
	}
	result.Warnings = append(result.Warnings, pendingWarnings...)
	if !timestampRecognized {
		result.Warnings = append(result.Warnings, makeWarning(
			WarningMalformed, sourceFile, lineNumber, raw,
			"authentication record has no recognized timestamp"))
	}

	event.Timestamp = timestamp
	event.Time = timestamp
	event.TimestampText = timestampText
	event.TimestampComplete = !timestamp.IsZero()
	event.SourceFile = sourceFile
	event.Filename = sourceFile
	event.LineNumber = lineNumber
	event.Line = lineNumber
	event.Raw = raw
	event.Host = host
	event.Process = process
	event.Message = body
	result.Event = &event
	return result
}

// ParseLine parses one line with the supplied case metadata.
func ParseLine(sourceFile string, lineNumber int, line string, metadata CaseMetadata) LineResult {
	return NewParser(metadata).ParseLine(sourceFile, lineNumber, line)
}

// ParseReader parses all lines from r.  Scanner failures are returned as
// warnings, so callers still receive events read before the failure.
func (p Parser) ParseReader(r io.Reader, sourceFile string) ParseResult {
	result := ParseResult{}
	if r == nil {
		result.Warnings = append(result.Warnings, makeWarning(
			WarningReader, sourceFile, 0, "", "cannot parse a nil reader"))
		return result
	}

	scanner := bufio.NewScanner(r)
	// Auth records are normally short, but avoid silently rejecting a long
	// journal export line.  This remains bounded and standard-library only.
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		lineResult := p.ParseLine(sourceFile, lineNumber, scanner.Text())
		if lineResult.Event != nil {
			result.Events = append(result.Events, *lineResult.Event)
		}
		result.Warnings = append(result.Warnings, lineResult.Warnings...)
	}
	if err := scanner.Err(); err != nil {
		result.Warnings = append(result.Warnings, makeWarning(
			WarningReader, sourceFile, lineNumber+1, "", fmt.Sprintf("reading source: %v", err)))
	}
	return result
}

// ParseReader parses all lines from r using the supplied metadata.
func ParseReader(r io.Reader, sourceFile string, metadata CaseMetadata) ParseResult {
	return NewParser(metadata).ParseReader(r, sourceFile)
}

// ParseAuthLog is a descriptive alias for ParseReader.
func ParseAuthLog(r io.Reader, sourceFile string, metadata CaseMetadata) ParseResult {
	return ParseReader(r, sourceFile, metadata)
}

// Parse parses an in-memory auth-log byte source while retaining the supplied
// logical filename in every event and warning.
func Parse(data []byte, sourceFile string, metadata CaseMetadata) ParseResult {
	return ParseReader(bytes.NewReader(data), sourceFile, metadata)
}

// ParseBytes is an explicit alias for Parse for callers that want to make the
// byte-oriented input visible at the call site.
func ParseBytes(data []byte, sourceFile string, metadata CaseMetadata) ParseResult {
	return Parse(data, sourceFile, metadata)
}

// ParseLines parses an in-memory source while retaining 1-based line numbers.
func (p Parser) ParseLines(sourceFile string, lines []string) ParseResult {
	result := ParseResult{}
	for index, line := range lines {
		lineResult := p.ParseLine(sourceFile, index+1, line)
		if lineResult.Event != nil {
			result.Events = append(result.Events, *lineResult.Event)
		}
		result.Warnings = append(result.Warnings, lineResult.Warnings...)
	}
	return result
}

// ParseAuthLines parses an in-memory auth-log source.
func ParseAuthLines(lines []string, sourceFile string, metadata CaseMetadata) ParseResult {
	return NewParser(metadata).ParseLines(sourceFile, lines)
}

var (
	syslogTimestampRE = regexp.MustCompile(`^(?:<\d+>)?([A-Za-z]{3})[ \t]+([0-9]{1,2})[ \t]+([0-9]{2}):([0-9]{2}):([0-9]{2})(?:[ \t]+(.*))?$`)
	isoTimestampRE    = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))(?:[ \t]+(.*))?$`)
	dateTimeRE        = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2})[ \t]+(\d{2}:\d{2}:\d{2})(?:[ \t]+(.*))?$`)

	failedRE      = regexp.MustCompile(`(?i)^failed[ \t]+([^ \t]+(?:/[^ \t]+)*)[ \t]+for[ \t]+(?:(?:invalid|illegal)[ \t]+user[ \t]+)?([^ \t]+)[ \t]+from[ \t]+([^ \t]+)`)
	invalidRE     = regexp.MustCompile(`(?i)^invalid[ \t]+user[ \t]+([^ \t]+)[ \t]+from[ \t]+([^ \t]+)`)
	acceptedRE    = regexp.MustCompile(`(?i)^accepted[ \t]+([^ \t]+(?:/[^ \t]+)*)[ \t]+for[ \t]+([^ \t]+)[ \t]+from[ \t]+([^ \t]+)`)
	suRE          = regexp.MustCompile(`(?i)^\(to[ \t]+([^\)]+)\)[ \t]+([^ \t]+)`)
	rootSessionRE = regexp.MustCompile(`(?i)session[ \t]+opened[ \t]+for[ \t]+user[ \t]+([^ \t\(]+)(?:\([^\)]*\))?[ \t]+by[ \t]+([^ \t\(]+)?`)
)

var monthNumbers = map[string]time.Month{
	"jan": time.January,
	"feb": time.February,
	"mar": time.March,
	"apr": time.April,
	"may": time.May,
	"jun": time.June,
	"jul": time.July,
	"aug": time.August,
	"sep": time.September,
	"oct": time.October,
	"nov": time.November,
	"dec": time.December,
}

// parseTimestamp returns the unconsumed part of a line even when a recognized
// syslog timestamp cannot be normalized.  That lets the caller retain the
// event and report exactly why its time is incomplete.
func parseTimestamp(line string, metadata CaseMetadata) (time.Time, string, string, bool, []string) {
	trimmed := strings.TrimSpace(line)
	if match := isoTimestampRE.FindStringSubmatch(trimmed); match != nil {
		timestamp, err := time.Parse(time.RFC3339Nano, match[1])
		if err != nil {
			return time.Time{}, match[1], trimmedAfterMatch(trimmed, match[1]), true,
				[]string{fmt.Sprintf("invalid RFC3339 timestamp %q: %v", match[1], err)}
		}
		return timestamp, match[1], match[2], true, nil
	}
	if match := dateTimeRE.FindStringSubmatch(trimmed); match != nil {
		location, locationWarning := metadata.location()
		timestamp, err := time.ParseInLocation("2006-01-02 15:04:05", match[1]+" "+match[2], location)
		warnings := []string{}
		if locationWarning != "" {
			warnings = append(warnings, locationWarning)
		}
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("invalid timestamp %q %q: %v", match[1], match[2], err))
			return time.Time{}, match[1] + " " + match[2], match[3], true, warnings
		}
		return timestamp, match[1] + " " + match[2], match[3], true, warnings
	}
	if match := syslogTimestampRE.FindStringSubmatch(trimmed); match != nil {
		month, ok := monthNumbers[strings.ToLower(match[1])]
		if !ok {
			return time.Time{}, strings.Join(match[1:6], " "), match[6], true,
				[]string{fmt.Sprintf("unknown syslog month %q", match[1])}
		}
		day, _ := strconv.Atoi(match[2])
		hour, _ := strconv.Atoi(match[3])
		minute, _ := strconv.Atoi(match[4])
		second, _ := strconv.Atoi(match[5])
		timestampText := fmt.Sprintf("%s %s %s", match[1], match[2], match[3]+":"+match[4]+":"+match[5])
		year := metadata.year()
		if year == 0 {
			return time.Time{}, timestampText, match[6], true,
				[]string{"syslog timestamp has no year; supply CaseMetadata.Year"}
		}
		location, locationWarning := metadata.location()
		warnings := []string{}
		if locationWarning != "" {
			warnings = append(warnings, locationWarning)
		}
		candidate := time.Date(year, month, day, hour, minute, second, 0, location)
		if candidate.Year() != year || candidate.Month() != month || candidate.Day() != day ||
			candidate.Hour() != hour || candidate.Minute() != minute || candidate.Second() != second {
			warnings = append(warnings, fmt.Sprintf("invalid syslog timestamp %q", timestampText))
			return time.Time{}, timestampText, match[6], true, warnings
		}
		return candidate, timestampText, match[6], true, warnings
	}
	return time.Time{}, "", trimmed, false, nil
}

func trimmedAfterMatch(line, timestamp string) string {
	if len(line) <= len(timestamp) {
		return ""
	}
	return strings.TrimSpace(line[len(timestamp):])
}

// splitHeader separates "host sshd[123]: message" from the message.  A
// timestamp followed directly by a message is also valid for fixtures.
func splitHeader(remainder string) (host, process, body string) {
	remainder = strings.TrimSpace(remainder)
	if remainder == "" {
		return "", "", ""
	}
	colon := strings.IndexByte(remainder, ':')
	if colon < 0 {
		return "", "", remainder
	}
	left := strings.TrimSpace(remainder[:colon])
	candidateBody := strings.TrimSpace(remainder[colon+1:])
	if !looksLikeHeader(left, candidateBody) {
		return "", "", remainder
	}
	parts := strings.Fields(left)
	if len(parts) == 0 {
		return "", "", candidateBody
	}
	process = parts[len(parts)-1]
	if bracket := strings.IndexByte(process, '['); bracket >= 0 {
		process = process[:bracket]
	}
	if len(parts) > 1 {
		host = parts[0]
	}
	return host, process, candidateBody
}

func looksLikeHeader(left, body string) bool {
	parts := strings.Fields(left)
	if len(parts) >= 2 {
		return true
	}
	if len(parts) == 1 {
		name := strings.ToLower(strings.TrimSuffix(parts[0], ":"))
		// Bare "sudo: ..." and "su: ..." fixtures are common.
		return name == "sudo" || name == "su" || name == "sshd" ||
			strings.HasPrefix(name, "sudo[") || strings.HasPrefix(name, "su[") || strings.HasPrefix(name, "sshd[")
	}
	return body != ""
}

func parseBody(body, process string) (Event, bool) {
	body = strings.TrimSpace(body)
	event := Event{}
	if match := failedRE.FindStringSubmatch(body); match != nil {
		event.Kind = EventFailedPassword
		event.AuthMethod = match[1]
		event.User = cleanToken(match[2])
		event.SourceIP = cleanToken(match[3])
		return event, true
	}
	if match := invalidRE.FindStringSubmatch(body); match != nil {
		event.Kind = EventInvalidUser
		event.User = cleanToken(match[1])
		event.SourceIP = cleanToken(match[2])
		return event, true
	}
	if match := acceptedRE.FindStringSubmatch(body); match != nil {
		event.Kind = EventAcceptedLogin
		event.AuthMethod = match[1]
		event.User = cleanToken(match[2])
		event.SourceIP = cleanToken(match[3])
		return event, true
	}

	processName := strings.ToLower(strings.TrimSpace(process))
	if match := suRE.FindStringSubmatch(body); match != nil && isRootUser(match[1]) {
		event.Kind = EventSudoToRoot
		event.TargetUser = cleanToken(match[1])
		event.User = cleanToken(match[2])
		event.ActorUser = event.User
		return event, true
	}
	if strings.Contains(strings.ToLower(body), "session opened") {
		if match := rootSessionRE.FindStringSubmatch(body); match != nil && isRootUser(match[1]) {
			target := cleanToken(match[1])
			actor := cleanToken(match[2])
			event.TargetUser = target
			event.ActorUser = actor
			event.User = actor
			if processName == "sudo" || processName == "su" || strings.Contains(strings.ToLower(body), "sudo:session") || strings.Contains(strings.ToLower(body), "su-l:session") {
				event.Kind = EventSudoToRoot
			} else {
				event.Kind = EventRootSession
			}
			return event, true
		}
	}

	// sudo's command audit record is formatted as:
	//   alice : TTY=pts/0 ; ... ; USER=root ; COMMAND=/bin/bash
	if processName == "sudo" || strings.HasPrefix(processName, "sudo[") {
		if actor, target, command, ok := parseSudoCommand(body); ok {
			event.Kind = EventSudo
			if isRootUser(target) {
				event.Kind = EventSudoToRoot
			}
			event.User = actor
			event.ActorUser = actor
			event.TargetUser = cleanToken(target)
			event.Command = command
			return event, true
		}
	}
	return Event{}, false
}

func parseSudoCommand(body string) (actor, target, command string, ok bool) {
	separator := strings.Index(body, " :")
	if separator < 0 {
		separator = strings.Index(body, ":")
	}
	if separator <= 0 {
		return "", "", "", false
	}
	actor = strings.TrimSpace(body[:separator])
	if actor == "" || strings.ContainsAny(actor, " \t") {
		return "", "", "", false
	}
	for _, part := range strings.Split(body[separator+1:], ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "USER=") {
			target = strings.TrimSpace(part[len("USER="):])
		}
		if strings.HasPrefix(strings.ToUpper(part), "COMMAND=") {
			command = strings.TrimSpace(part[len("COMMAND="):])
		}
	}
	return actor, target, command, target != ""
}

func cleanToken(token string) string {
	return strings.Trim(token, " \t,;\"'")
}

func isRootUser(user string) bool {
	user = strings.ToLower(cleanToken(user))
	return user == "root" || user == "0"
}

func looksLikeAuthenticationRecord(line string) bool {
	lower := strings.ToLower(line)
	for _, marker := range []string{
		"failed password", "invalid user", "accepted ", "session opened", "sudo", "(to root)", "pam_unix", "connection closed", "preauth",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func makeWarning(kind WarningKind, sourceFile string, lineNumber int, raw, message string) Warning {
	return Warning{
		Kind:       kind,
		Message:    message,
		SourceFile: sourceFile,
		Filename:   sourceFile,
		LineNumber: lineNumber,
		Line:       lineNumber,
		Raw:        raw,
	}
}

type eventIdentity struct {
	timestampKnown bool
	timestampSec   int64
	timestampNano  int
	timestampText  string
	kind           EventKind
	host           string
	process        string
	user           string
	actorUser      string
	targetUser     string
	sourceIP       string
	authMethod     string
	command        string
	message        string
}

func identityOf(event Event) eventIdentity {
	identity := eventIdentity{
		timestampText: event.TimestampText,
		kind:          event.Kind,
		host:          event.Host,
		process:       event.Process,
		user:          event.User,
		actorUser:     event.ActorUser,
		targetUser:    event.TargetUser,
		sourceIP:      event.SourceIP,
		authMethod:    event.AuthMethod,
		command:       event.Command,
		message:       event.Message,
	}
	if !event.Timestamp.IsZero() {
		utc := event.Timestamp.UTC()
		identity.timestampKnown = true
		identity.timestampSec = utc.Unix()
		identity.timestampNano = utc.Nanosecond()
	}
	return identity
}

func sourceReferenceOf(event Event) SourceReference {
	sourceFile := event.SourceFile
	if sourceFile == "" {
		sourceFile = event.Filename
	}
	filename := event.Filename
	if filename == "" {
		filename = sourceFile
	}
	lineNumber := event.LineNumber
	if lineNumber == 0 {
		lineNumber = event.Line
	}
	line := event.Line
	if line == 0 {
		line = lineNumber
	}
	return SourceReference{
		SourceFile: sourceFile,
		Filename:   filename,
		LineNumber: lineNumber,
		Line:       line,
		Raw:        event.Raw,
	}
}

func referencesOf(event Event) []SourceReference {
	if len(event.SourceReferences) != 0 {
		return append([]SourceReference(nil), event.SourceReferences...)
	}
	return []SourceReference{sourceReferenceOf(event)}
}

// DeduplicateEvents returns a stable canonical event for each semantically
// identical parsed event.  Source location and raw text are deliberately not
// part of identity, so copies found in different files collapse while all
// occurrences remain available in SourceReferences.  The normalized event
// fields, including the full message and timestamp, make the identity
// conservative: sharing a timestamp alone can never collapse two events.
//
// The input slice and its events are not modified.  The legacy source fields
// on each canonical event retain the first occurrence for compatibility.
func DeduplicateEvents(events []Event) []Event {
	result := make([]Event, 0, len(events))
	seen := make(map[eventIdentity]int, len(events))
	for _, input := range events {
		event := input
		event.SourceReferences = referencesOf(input)
		identity := identityOf(input)
		if index, ok := seen[identity]; ok {
			result[index].SourceReferences = append(result[index].SourceReferences, event.SourceReferences...)
			continue
		}
		seen[identity] = len(result)
		result = append(result, event)
	}
	return result
}

// Timeline is a deterministic chronological copy of parsed events.  Events
// with incomplete timestamps are retained after normalized events in source
// order, because dropping them would lose useful evidence.
type Timeline struct {
	Events []Event
}

// BuildTimeline returns a sorted copy and never changes its input slice.
func BuildTimeline(events []Event) Timeline {
	sortedEvents := append([]Event(nil), events...)
	sort.SliceStable(sortedEvents, func(i, j int) bool {
		left, right := sortedEvents[i], sortedEvents[j]
		leftKnown, rightKnown := !left.Timestamp.IsZero(), !right.Timestamp.IsZero()
		if leftKnown != rightKnown {
			return leftKnown
		}
		if leftKnown && !left.Timestamp.Equal(right.Timestamp) {
			return left.Timestamp.Before(right.Timestamp)
		}
		if left.SourceFile != right.SourceFile {
			return left.SourceFile < right.SourceFile
		}
		if left.LineNumber != right.LineNumber {
			return left.LineNumber < right.LineNumber
		}
		return left.Kind < right.Kind
	})
	return Timeline{Events: sortedEvents}
}

// ChronologicalTimeline is a slice-oriented convenience wrapper.
func ChronologicalTimeline(events []Event) []Event { return BuildTimeline(events).Events }

// Len and At make Timeline convenient for callers that do not need to expose
// its representation to later integrations.
func (t Timeline) Len() int { return len(t.Events) }

func (t Timeline) At(index int) (Event, bool) {
	if index < 0 || index >= len(t.Events) {
		return Event{}, false
	}
	return t.Events[index], true
}

// RuleID identifies one deterministic analysis rule.
type RuleID string

const (
	RuleBruteForce                   RuleID = "brute_force"
	RuleSuccessAfterFailures         RuleID = "success_after_failures"
	RulePrivilegeEscalation          RuleID = "privilege_escalation_after_login"
	RuleSuccessfulLoginAfterFailures RuleID = RuleSuccessAfterFailures
	RuleSudoAfterLogin               RuleID = RulePrivilegeEscalation
)

// Severity is intentionally small and stable for later renderers.
type Severity string

const (
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

// Finding is a deterministic rule result with the source events that caused
// it.  SourceFile and LineNumber point to the triggering event.
type Finding struct {
	Rule      RuleID
	Severity  Severity
	Message   string
	Timestamp time.Time

	SourceIP   string
	User       string
	SourceFile string
	LineNumber int

	FailureCount int
	Explicit     bool
	Potential    bool
	Evidence     []Event
}

// RuleConfig controls the default deterministic rules.  Zero values select
// the CAIRN defaults: five failures in ten minutes, a fifteen-minute success
// correlation window, and a fifteen-minute privilege escalation age.
type RuleConfig struct {
	FailureThreshold          int
	FailureWindow             time.Duration
	SuccessWindow             time.Duration
	PrivilegeEscalationWindow time.Duration
}

func (c RuleConfig) normalized() RuleConfig {
	if c.FailureThreshold <= 0 {
		c.FailureThreshold = 5
	}
	if c.FailureWindow <= 0 {
		c.FailureWindow = 10 * time.Minute
	}
	if c.SuccessWindow <= 0 {
		c.SuccessWindow = 15 * time.Minute
	}
	if c.PrivilegeEscalationWindow <= 0 {
		c.PrivilegeEscalationWindow = 15 * time.Minute
	}
	return c
}

// Analysis is the complete input-independent result.
type Analysis struct {
	Timeline Timeline
	Events   []Event
	Findings []Finding
	Warnings []Warning
}

// Analyze applies the default CAIRN rules.
func Analyze(events []Event) Analysis { return AnalyzeWithConfig(events, RuleConfig{}) }

// AnalyzeEvents returns only findings for callers that already own timeline
// and warning handling.
func AnalyzeEvents(events []Event) []Finding { return Analyze(events).Findings }

// AnalyzeWithConfig applies deterministic rules to a chronological copy of
// events.  It does not mutate the caller's slice.
func AnalyzeWithConfig(events []Event, config RuleConfig) Analysis {
	config = config.normalized()
	events = DeduplicateEvents(events)
	timeline := BuildTimeline(events)
	analysis := Analysis{Timeline: timeline, Events: timeline.Events}

	failuresBySource := make(map[string][]Event)
	bruteForceActive := make(map[string]bool)
	loginsByUser := make(map[string][]Event)

	for _, event := range timeline.Events {
		if event.Timestamp.IsZero() {
			continue
		}

		if isFailure(event) && event.SourceIP != "" {
			failures := append(failuresBySource[event.SourceIP], event)
			failures = retainRecent(failures, event.Timestamp, config.SuccessWindow)
			failuresBySource[event.SourceIP] = failures

			withinFailureWindow := retainRecent(failures, event.Timestamp, config.FailureWindow)
			if len(withinFailureWindow) < config.FailureThreshold {
				bruteForceActive[event.SourceIP] = false
			} else if !bruteForceActive[event.SourceIP] {
				bruteForceActive[event.SourceIP] = true
				analysis.Findings = append(analysis.Findings, Finding{
					Rule:         RuleBruteForce,
					Severity:     SeverityHigh,
					Message:      fmt.Sprintf("source %s produced %d failed authentications within %s", event.SourceIP, len(withinFailureWindow), config.FailureWindow),
					Timestamp:    event.Timestamp,
					SourceIP:     event.SourceIP,
					User:         event.User,
					SourceFile:   event.SourceFile,
					LineNumber:   event.LineNumber,
					FailureCount: len(withinFailureWindow),
					Evidence:     append([]Event(nil), withinFailureWindow...),
				})
			}
		}

		if event.Kind == EventAcceptedLogin {
			if event.SourceIP != "" {
				failures := retainRecent(failuresBySource[event.SourceIP], event.Timestamp, config.SuccessWindow)
				failuresBySource[event.SourceIP] = failures
				failuresInFailureWindow := retainRecent(append([]Event(nil), failures...), event.Timestamp, config.FailureWindow)
				if len(failuresInFailureWindow) >= config.FailureThreshold {
					analysis.Findings = append(analysis.Findings, Finding{
						Rule:         RuleSuccessAfterFailures,
						Severity:     SeverityHigh,
						Message:      fmt.Sprintf("successful login for %s followed failures from source %s within %s", event.User, event.SourceIP, config.SuccessWindow),
						Timestamp:    event.Timestamp,
						SourceIP:     event.SourceIP,
						User:         event.User,
						SourceFile:   event.SourceFile,
						LineNumber:   event.LineNumber,
						FailureCount: len(failuresInFailureWindow),
						Evidence:     append([]Event(nil), failuresInFailureWindow...),
					})
				}
			}
			if event.User != "" {
				loginsByUser[event.User] = append(loginsByUser[event.User], event)
			}
		}

		if event.Kind == EventSudoToRoot || event.Kind == EventRootSession {
			actor := event.ActorUser
			if actor == "" {
				actor = event.User
			}
			if login, ok := latestMatchingLogin(loginsByUser[actor], event, config.PrivilegeEscalationWindow); ok {
				explicit := event.Kind == EventSudoToRoot
				word := "potential root-session escalation"
				if explicit {
					word = "sudo-to-root escalation"
				}
				analysis.Findings = append(analysis.Findings, Finding{
					Rule:       RulePrivilegeEscalation,
					Severity:   SeverityHigh,
					Message:    fmt.Sprintf("%s by %s followed successful login at %s", word, actor, login.Timestamp.Format(time.RFC3339)),
					Timestamp:  event.Timestamp,
					SourceIP:   event.SourceIP,
					User:       actor,
					SourceFile: event.SourceFile,
					LineNumber: event.LineNumber,
					Explicit:   explicit,
					Potential:  !explicit,
					Evidence:   []Event{login, event},
				})
			}
		}
	}
	return analysis
}

// AnalyzeParsed analyzes parser output and carries parser warnings through to
// the returned analysis.
func AnalyzeParsed(parsed ParseResult) Analysis {
	analysis := Analyze(parsed.Events)
	analysis.Warnings = append(analysis.Warnings, parsed.Warnings...)
	return analysis
}

func isFailure(event Event) bool {
	return event.Kind == EventFailedPassword || event.Kind == EventInvalidUser
}

func retainRecent(events []Event, current time.Time, window time.Duration) []Event {
	start := current.Add(-window)
	kept := events[:0]
	for _, event := range events {
		if !event.Timestamp.IsZero() && !event.Timestamp.Before(start) && !event.Timestamp.After(current) {
			kept = append(kept, event)
		}
	}
	return kept
}

func latestMatchingLogin(logins []Event, escalation Event, maxAge time.Duration) (Event, bool) {
	actor := escalation.ActorUser
	if actor == "" {
		actor = escalation.User
	}
	for index := len(logins) - 1; index >= 0; index-- {
		login := logins[index]
		if login.Timestamp.IsZero() || login.Timestamp.After(escalation.Timestamp) {
			continue
		}
		if escalation.Timestamp.Sub(login.Timestamp) > maxAge {
			continue
		}
		if escalation.SourceIP != "" && login.SourceIP != "" && escalation.SourceIP != login.SourceIP {
			continue
		}
		if actor == "" || login.User == actor {
			return login, true
		}
	}
	return Event{}, false
}
