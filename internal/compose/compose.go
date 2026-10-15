// Package compose contains a small, syntax-aware security audit for Docker
// Compose documents. It deliberately works from yaml.Node values instead of
// unmarshalling into map[string]any so findings can point back to the source
// location of the setting that caused them.
package compose

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

// Severity is the impact assigned to a finding.
const (
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Rule IDs emitted by the Compose auditor.
const (
	RulePrivileged         = "privileged"
	RuleHostNetwork        = "host-network"
	RuleHostPID            = "host-pid"
	RuleHostIPC            = "host-ipc"
	RuleDockerSocket       = "docker-socket"
	RuleSensitiveHostMount = "sensitive-host-mount"
	RuleCapAddSYSAdmin     = "cap-add-sys-admin"
	RuleCapAddNETAdmin     = "cap-add-net-admin"
	RuleCapAddALL          = "cap-add-all"
	RuleSeccompUnconfined  = "seccomp-unconfined"
	RuleAppArmorUnconfined = "apparmor-unconfined"
)

// Go-style acronym aliases keep rule constants convenient for callers that
// prefer mixed-case names while the uppercase forms remain descriptive.
const (
	RuleHostPid            = RuleHostPID
	RuleHostIpc            = RuleHostIPC
	RuleCapAddSysAdmin     = RuleCapAddSYSAdmin
	RuleCapAddNetAdmin     = RuleCapAddNETAdmin
	RuleCapAddAll          = RuleCapAddALL
	RuleApparmorUnconfined = RuleAppArmorUnconfined
)

// Finding is an evidence-backed security finding for one Compose service.
//
// Line and Column are one-based YAML coordinates when yaml.v3 supplied a
// coordinate, and are zero when the input node had no source coordinate (for
// example, a Document assembled by a caller rather than decoded from YAML).
// Source and SourceRef contain the same stable, human-readable YAML path. The
// duplicate name makes the type convenient for callers that use either term.
type Finding struct {
	Service     string
	ServiceName string
	SourceFile  string
	Filename    string
	File        string
	Source      string
	SourceRef   string
	LineNumber  int
	Line        int
	Column      int
	RuleID      string
	Rule        string
	Severity    string
	Message     string
	Explanation string
	Remediation string
	Raw         string
	Evidence    string
}

// Service is a Compose service entry in source order.
type Service struct {
	Name string
	Node *yaml.Node
}

// Document is a decoded Compose YAML document. The root is retained as a
// yaml.Node so callers can inspect source coordinates or build their own
// checks without losing the original structure.
type Document struct {
	Filename string
	Root     *yaml.Node
}

// LoadBytes decodes one Compose YAML document from data. filename is recorded
// on findings and may be a logical name such as "compose.yaml". An empty
// filename is represented as "<bytes>" in the returned document.
func LoadBytes(data []byte, filename string) (*Document, error) {
	if filename == "" {
		filename = "<bytes>"
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		if err == io.EOF {
			// An empty input is a valid empty YAML document. It simply has no
			// services to audit.
			return &Document{Filename: filename}, nil
		}
		return nil, yamlError(filename, err)
	}
	if err := validateNode(&root); err != nil {
		return nil, yamlError(filename, err)
	}

	// Compose accepts one document. Rejecting a second document avoids silently
	// auditing one configuration while a caller believes another was loaded.
	var extra yaml.Node
	if err := decoder.Decode(&extra); err == nil {
		return nil, fmt.Errorf("compose: %s contains more than one YAML document", filename)
	} else if err != io.EOF {
		return nil, yamlError(filename, err)
	}

	return &Document{Filename: filename, Root: &root}, nil
}

// Load is a short alias for LoadBytes.
func Load(data []byte, filename string) (*Document, error) {
	return LoadBytes(data, filename)
}

// Parse is an alias for LoadBytes for callers that prefer parser terminology.
func Parse(data []byte, filename string) (*Document, error) {
	return LoadBytes(data, filename)
}

// LoadFile reads and decodes a Compose YAML document from path.
func LoadFile(pathname string) (*Document, error) {
	data, err := os.ReadFile(pathname)
	if err != nil {
		return nil, fmt.Errorf("compose: read %s: %w", pathname, err)
	}
	return LoadBytes(data, pathname)
}

// LoadPath is an explicit-name alias for LoadFile.
func LoadPath(pathname string) (*Document, error) {
	return LoadFile(pathname)
}

// Audit decodes data and returns all findings in service and source order.
func Audit(data []byte, filename string) ([]Finding, error) {
	document, err := LoadBytes(data, filename)
	if err != nil {
		return nil, err
	}
	return document.Audit(), nil
}

// AuditBytes is an explicit-name alias for Audit.
func AuditBytes(data []byte, filename string) ([]Finding, error) {
	return Audit(data, filename)
}

// AuditFile reads path and returns all findings in service and source order.
func AuditFile(pathname string) ([]Finding, error) {
	document, err := LoadFile(pathname)
	if err != nil {
		return nil, err
	}
	return document.Audit(), nil
}

// Services returns service entries in their YAML source order. Invalid or
// missing services sections are treated as empty; they are not a reason to
// panic or to invent a service from an oddly typed value.
func (d *Document) Services() []Service {
	if d == nil {
		return nil
	}

	root := documentRoot(d.Root)
	services := mappingValue(root, "services")
	services = resolveAlias(services)
	if services == nil || services.Kind != yaml.MappingNode {
		return nil
	}

	result := make([]Service, 0, len(services.Content)/2)
	for i := 0; i+1 < len(services.Content); i += 2 {
		nameNode := resolveAlias(services.Content[i])
		serviceNode := services.Content[i+1]
		name, ok := scalarText(nameNode)
		if !ok {
			continue
		}
		result = append(result, Service{Name: name, Node: serviceNode})
	}
	return result
}

// VisitServices calls visit once for each valid service in source order. A
// nil callback is a no-op, which keeps callers safe when the services section
// is optional.
func (d *Document) VisitServices(visit func(Service)) {
	if visit == nil {
		return
	}
	for _, service := range d.Services() {
		visit(service)
	}
}

// Audit runs all built-in rules over the document. It returns an empty slice
// for a nil document, an empty YAML document, or a document without a usable
// services mapping.
func (d *Document) Audit() []Finding {
	findings := make([]Finding, 0)
	if d == nil {
		return findings
	}
	for _, service := range d.Services() {
		findings = append(findings, auditService(d.Filename, service)...)
	}
	return findings
}

// Findings is an alias for Audit.
func (d *Document) Findings() []Finding {
	return d.Audit()
}

func auditService(filename string, service Service) []Finding {
	findings := make([]Finding, 0)
	serviceNode := resolveAlias(service.Node)

	if key, value, ok := mappingEntry(serviceNode, "privileged"); ok && isTrue(value) {
		findings = append(findings, makeFinding(
			filename, service.Name, key, value, sourcePath(service.Name, "privileged"),
			RulePrivileged, SeverityCritical,
			"The service enables privileged container mode, which removes most container isolation.",
			"Remove privileged mode and grant only the specific device, capability, or permission the service needs.",
			scalarEvidence(value, "true"),
		))
	}

	for _, hostRule := range []struct {
		field       string
		ruleID      string
		explanation string
	}{
		{field: "network_mode", ruleID: RuleHostNetwork, explanation: "The service shares the host network namespace."},
		{field: "pid", ruleID: RuleHostPID, explanation: "The service shares the host PID namespace."},
		{field: "ipc", ruleID: RuleHostIPC, explanation: "The service shares the host IPC namespace."},
	} {
		key, value, ok := mappingEntry(serviceNode, hostRule.field)
		if !ok || !isHost(value) {
			continue
		}
		findings = append(findings, makeFinding(
			filename, service.Name, key, value, sourcePath(service.Name, hostRule.field),
			hostRule.ruleID, SeverityHigh,
			hostRule.explanation,
			"Use an isolated namespace and expose only the narrowly scoped network, process, or IPC access required by the service.",
			scalarEvidence(value, "host"),
		))
	}

	if _, volumes, ok := mappingEntry(serviceNode, "volumes"); ok {
		findings = append(findings, auditVolumes(filename, service.Name, volumes)...)
	}

	if _, caps, ok := mappingEntry(serviceNode, "cap_add"); ok {
		findings = append(findings, auditCapabilities(filename, service.Name, caps)...)
	}

	if _, options, ok := mappingEntry(serviceNode, "security_opt"); ok {
		findings = append(findings, auditSecurityOptions(filename, service.Name, options)...)
	}

	return findings
}

func auditVolumes(filename, service string, value *yaml.Node) []Finding {
	volumes := resolveAlias(value)
	if volumes == nil || volumes.Kind != yaml.SequenceNode {
		return nil
	}

	findings := make([]Finding, 0)
	for index, item := range volumes.Content {
		mount := parseMount(item)
		if !mount.valid {
			continue
		}
		itemNode := item
		if mount.location != nil {
			itemNode = mount.location
		}
		if isDockerSocketPath(mount.source) {
			findings = append(findings, makeFinding(
				filename, service, itemNode, item,
				sourcePathIndex(service, "volumes", index), RuleDockerSocket, SeverityCritical,
				"The service mounts a Docker socket and can potentially control the Docker daemon.",
				"Remove the Docker socket mount; use a narrowly scoped API or an isolated builder when daemon access is required.",
				mount.evidence,
			))
			continue
		}
		if isSensitiveHostPath(mount.source) {
			findings = append(findings, makeFinding(
				filename, service, itemNode, item,
				sourcePathIndex(service, "volumes", index), RuleSensitiveHostMount, SeverityHigh,
				"The service mounts a sensitive path from the host, weakening filesystem isolation.",
				"Remove the host bind mount or replace it with a narrowly scoped, read-only application directory.",
				mount.evidence,
			))
		}
	}
	return findings
}

func auditCapabilities(filename, service string, value *yaml.Node) []Finding {
	value = resolveAlias(value)
	if value == nil {
		return nil
	}

	items := make([]*yaml.Node, 0)
	switch value.Kind {
	case yaml.SequenceNode:
		items = append(items, value.Content...)
	case yaml.ScalarNode:
		// Compose documents normally use a sequence, but accepting one scalar
		// makes the auditor safe and useful on hand-written or generated input.
		items = append(items, value)
	default:
		return nil
	}

	findings := make([]Finding, 0)
	for index, item := range items {
		capability, ok := scalarText(item)
		if !ok {
			continue
		}
		ruleID, severity, normalized, ok := capabilityRule(capability)
		if !ok {
			continue
		}
		source := sourcePathIndex(service, "cap_add", index)
		if value.Kind == yaml.ScalarNode {
			source = sourcePath(service, "cap_add")
		}
		findings = append(findings, makeFinding(
			filename, service, item, value, source, ruleID, severity,
			"The service adds the high-risk "+normalized+" Linux capability.",
			"Remove the capability; if it is unavoidable, replace it with the least-privileged capability set and document the need.",
			strings.TrimSpace(capability),
		))
	}
	return findings
}

func auditSecurityOptions(filename, service string, value *yaml.Node) []Finding {
	value = resolveAlias(value)
	if value == nil {
		return nil
	}

	items := make([]*yaml.Node, 0)
	switch value.Kind {
	case yaml.SequenceNode:
		items = append(items, value.Content...)
	case yaml.ScalarNode:
		items = append(items, value)
	default:
		return nil
	}

	findings := make([]Finding, 0)
	for index, item := range items {
		option, ok := scalarText(item)
		if !ok {
			continue
		}
		key, optionValue, ok := securityOption(option)
		if !ok || !strings.EqualFold(optionValue, "unconfined") {
			continue
		}

		ruleID := RuleSeccompUnconfined
		explanation := "The service disables the default seccomp profile."
		remediation := "Use the default seccomp profile or provide a narrowly scoped custom profile."
		if key == "apparmor" {
			ruleID = RuleAppArmorUnconfined
			explanation = "The service disables AppArmor confinement."
			remediation = "Use the default AppArmor profile or provide a narrowly scoped custom profile."
		} else if key != "seccomp" {
			continue
		}

		source := sourcePathIndex(service, "security_opt", index)
		if value.Kind == yaml.ScalarNode {
			source = sourcePath(service, "security_opt")
		}
		findings = append(findings, makeFinding(
			filename, service, item, value, source, ruleID, SeverityHigh,
			explanation, remediation, strings.TrimSpace(option),
		))
	}
	return findings
}

type mount struct {
	valid    bool
	source   string
	target   string
	evidence string
	location *yaml.Node
}

func parseMount(node *yaml.Node) mount {
	original := node
	node = resolveAlias(node)
	if node == nil {
		return mount{}
	}

	if node.Kind == yaml.ScalarNode {
		value := strings.TrimSpace(node.Value)
		parts := strings.Split(value, ":")
		if len(parts) < 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return mount{}
		}
		return mount{
			valid:    true,
			source:   strings.TrimSpace(parts[0]),
			target:   strings.TrimSpace(parts[1]),
			evidence: value,
			location: original,
		}
	}

	if node.Kind != yaml.MappingNode {
		return mount{}
	}
	sourceNode := mappingValue(node, "source")
	targetNode := mappingValue(node, "target")
	typeNode := mappingValue(node, "type")
	source, sourceOK := scalarText(sourceNode)
	target, targetOK := scalarText(targetNode)
	if !sourceOK || !targetOK || strings.TrimSpace(source) == "" || strings.TrimSpace(target) == "" {
		return mount{}
	}
	mountType, _ := scalarText(typeNode)
	if mountType != "" && !strings.EqualFold(strings.TrimSpace(mountType), "bind") {
		return mount{}
	}
	return mount{
		valid:    true,
		source:   strings.TrimSpace(source),
		target:   strings.TrimSpace(target),
		evidence: strings.TrimSpace(source) + ":" + strings.TrimSpace(target),
		location: original,
	}
}

func capabilityRule(value string) (ruleID, severity, normalized string, ok bool) {
	normalized = strings.ToUpper(strings.TrimSpace(value))
	if strings.HasPrefix(normalized, "CAP_") {
		normalized = strings.TrimPrefix(normalized, "CAP_")
	}
	switch normalized {
	case "SYS_ADMIN":
		return RuleCapAddSYSAdmin, SeverityHigh, "SYS_ADMIN", true
	case "NET_ADMIN":
		return RuleCapAddNETAdmin, SeverityHigh, "NET_ADMIN", true
	case "ALL":
		return RuleCapAddALL, SeverityCritical, "ALL", true
	default:
		return "", "", "", false
	}
}

func securityOption(value string) (key, optionValue string, ok bool) {
	value = strings.TrimSpace(value)
	separator := strings.IndexByte(value, '=')
	if separator < 0 {
		separator = strings.IndexByte(value, ':')
	}
	if separator <= 0 || separator == len(value)-1 {
		return "", "", false
	}
	return strings.ToLower(strings.TrimSpace(value[:separator])), strings.TrimSpace(value[separator+1:]), true
}

func isDockerSocketPath(value string) bool {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if value == "" {
		return false
	}
	clean := path.Clean(value)
	return strings.EqualFold(path.Base(clean), "docker.sock")
}

func isSensitiveHostPath(value string) bool {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if value == "" || isDockerSocketPath(value) {
		return false
	}
	clean := path.Clean(value)
	if !strings.HasPrefix(clean, "/") {
		return false
	}

	for _, sensitive := range []string{
		"/",
		"/boot",
		"/dev",
		"/etc",
		"/home",
		"/proc",
		"/root",
		"/run",
		"/sys",
		"/var",
		"/var/lib/containerd",
		"/var/lib/docker",
		"/var/run",
	} {
		if clean == sensitive || strings.HasPrefix(clean, sensitive+"/") {
			return true
		}
	}
	return false
}

func makeFinding(filename, service string, primary, fallback *yaml.Node, source, ruleID, severity, explanation, remediation, evidence string) Finding {
	line, column := nodeLocation(primary)
	if line == 0 {
		line, column = nodeLocation(fallback)
	}
	return Finding{
		Service:     service,
		ServiceName: service,
		SourceFile:  filename,
		Filename:    filename,
		File:        filename,
		Source:      source,
		SourceRef:   source,
		LineNumber:  line,
		Line:        line,
		Column:      column,
		RuleID:      ruleID,
		Rule:        ruleID,
		Severity:    severity,
		Message:     explanation,
		Explanation: explanation,
		Remediation: remediation,
		Raw:         evidence,
		Evidence:    evidence,
	}
}

func sourcePath(service, field string) string {
	return "services." + service + "." + field
}

func sourcePathIndex(service, field string, index int) string {
	return fmt.Sprintf("services.%s.%s[%d]", service, field, index)
}

func scalarEvidence(node *yaml.Node, fallback string) string {
	if value, ok := scalarText(node); ok {
		return strings.TrimSpace(value)
	}
	return fallback
}

func yamlError(filename string, err error) error {
	return fmt.Errorf("compose: invalid YAML in %s: %w", filename, err)
}

func documentRoot(root *yaml.Node) *yaml.Node {
	root = resolveAlias(root)
	if root == nil {
		return nil
	}
	if root.Kind == yaml.DocumentNode {
		if len(root.Content) == 0 {
			return nil
		}
		return resolveAlias(root.Content[0])
	}
	return root
}

func mappingEntry(node *yaml.Node, key string) (keyNode, valueNode *yaml.Node, ok bool) {
	return mappingEntrySeen(node, key, make(map[*yaml.Node]bool))
}

func mappingEntrySeen(node *yaml.Node, key string, seen map[*yaml.Node]bool) (keyNode, valueNode *yaml.Node, ok bool) {
	node = resolveAlias(node)
	if node == nil || node.Kind != yaml.MappingNode {
		return nil, nil, false
	}
	if seen[node] {
		return nil, nil, false
	}
	seen[node] = true
	defer delete(seen, node)

	for i := 0; i+1 < len(node.Content); i += 2 {
		candidate := resolveAlias(node.Content[i])
		if candidate != nil && candidate.Kind == yaml.ScalarNode && candidate.Value == key {
			return node.Content[i], node.Content[i+1], true
		}
	}

	// YAML merge keys are common in Compose files. Direct service values above
	// take precedence, matching YAML's merge semantics; inherited values are
	// still audited when a service does not override them. The cycle guard also
	// makes self-referential or otherwise odd aliases harmless.
	for i := 0; i+1 < len(node.Content); i += 2 {
		mergeKey := resolveAlias(node.Content[i])
		if mergeKey == nil || mergeKey.Kind != yaml.ScalarNode || mergeKey.Value != "<<" {
			continue
		}
		merged := resolveAlias(node.Content[i+1])
		if merged == nil {
			continue
		}
		if merged.Kind == yaml.SequenceNode {
			for _, item := range merged.Content {
				if keyNode, valueNode, ok := mappingEntrySeen(item, key, seen); ok {
					return keyNode, valueNode, true
				}
			}
			continue
		}
		if keyNode, valueNode, ok := mappingEntrySeen(merged, key, seen); ok {
			return keyNode, valueNode, true
		}
	}
	return nil, nil, false
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	_, value, ok := mappingEntry(node, key)
	if !ok {
		return nil
	}
	return value
}

func scalarText(node *yaml.Node) (string, bool) {
	node = resolveAlias(node)
	if node == nil || node.Kind != yaml.ScalarNode {
		return "", false
	}
	return node.Value, true
}

func isTrue(node *yaml.Node) bool {
	node = resolveAlias(node)
	if node == nil || node.Kind != yaml.ScalarNode || node.Tag != "!!bool" {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(node.Value), "true")
}

func isHost(node *yaml.Node) bool {
	value, ok := scalarText(node)
	return ok && strings.EqualFold(strings.TrimSpace(value), "host")
}

func nodeLocation(node *yaml.Node) (line, column int) {
	node = resolveAlias(node)
	if node == nil {
		return 0, 0
	}
	return node.Line, node.Column
}

func resolveAlias(node *yaml.Node) *yaml.Node {
	seen := make(map[*yaml.Node]struct{})
	for node != nil && node.Kind == yaml.AliasNode && node.Alias != nil {
		if _, ok := seen[node]; ok {
			return node
		}
		seen[node] = struct{}{}
		node = node.Alias
	}
	return node
}

// validateNode supplies the duplicate-key check that yaml.v3 intentionally
// does not apply when decoding into yaml.Node. Duplicate keys are ambiguous
// across Compose implementations, so rejecting them is safer than silently
// auditing one of the competing values. The walk is defensive about odd
// Content lengths and cyclic aliases because this package also exposes the
// decoded node to callers.
func validateNode(root *yaml.Node) error {
	return validateNodeVisit(root, make(map[*yaml.Node]bool), make(map[*yaml.Node]bool))
}

func validateNodeVisit(node *yaml.Node, visiting, visited map[*yaml.Node]bool) error {
	if node == nil {
		return nil
	}
	if visiting[node] {
		return nil
	}
	if visited[node] {
		return nil
	}
	visiting[node] = true
	defer delete(visiting, node)
	visited[node] = true

	if node.Kind == yaml.AliasNode {
		return validateNodeVisit(node.Alias, visiting, visited)
	}
	if node.Kind == yaml.MappingNode {
		keys := make(map[string]*yaml.Node, len(node.Content)/2)
		for index := 0; index+1 < len(node.Content); index += 2 {
			keyNode := node.Content[index]
			key := resolveAlias(keyNode)
			if key != nil && key.Kind == yaml.ScalarNode {
				identity := key.Tag + "\x00" + key.Value
				if previous, exists := keys[identity]; exists {
					return fmt.Errorf("duplicate mapping key %q at line %d, column %d (first at line %d, column %d)", key.Value, keyNode.Line, keyNode.Column, previous.Line, previous.Column)
				}
				keys[identity] = keyNode
			}
			if err := validateNodeVisit(keyNode, visiting, visited); err != nil {
				return err
			}
			if err := validateNodeVisit(node.Content[index+1], visiting, visited); err != nil {
				return err
			}
		}
		return nil
	}
	for _, child := range node.Content {
		if err := validateNodeVisit(child, visiting, visited); err != nil {
			return err
		}
	}
	return nil
}
