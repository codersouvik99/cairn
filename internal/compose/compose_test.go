package compose

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditDangerousSettings(t *testing.T) {
	tests := []struct {
		name     string
		compose  string
		ruleID   string
		service  string
		evidence string
	}{
		{
			name: "privileged",
			compose: `services:
  api:
    privileged: true
`,
			ruleID:  RulePrivileged,
			service: "api",
		},
		{
			name: "host network",
			compose: `services:
  api:
    network_mode: host
`,
			ruleID:  RuleHostNetwork,
			service: "api",
		},
		{
			name: "host pid",
			compose: `services:
  api:
    pid: host
`,
			ruleID:  RuleHostPID,
			service: "api",
		},
		{
			name: "host ipc",
			compose: `services:
  api:
    ipc: host
`,
			ruleID:  RuleHostIPC,
			service: "api",
		},
		{
			name: "docker socket short syntax",
			compose: `services:
  builder:
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`,
			ruleID:   RuleDockerSocket,
			service:  "builder",
			evidence: "/var/run/docker.sock",
		},
		{
			name: "docker socket long syntax",
			compose: `services:
  builder:
    volumes:
      - type: bind
        source: /run/docker.sock
        target: /var/run/docker.sock
`,
			ruleID:   RuleDockerSocket,
			service:  "builder",
			evidence: "/run/docker.sock",
		},
		{
			name: "sensitive host mount",
			compose: `services:
  api:
    volumes:
      - /etc:/host/etc:ro
`,
			ruleID:   RuleSensitiveHostMount,
			service:  "api",
			evidence: "/etc",
		},
		{
			name: "sys admin capability",
			compose: `services:
  api:
    cap_add:
      - SYS_ADMIN
`,
			ruleID:   RuleCapAddSYSAdmin,
			service:  "api",
			evidence: "SYS_ADMIN",
		},
		{
			name: "net admin capability",
			compose: `services:
  api:
    cap_add:
      - CAP_NET_ADMIN
`,
			ruleID:   RuleCapAddNETAdmin,
			service:  "api",
			evidence: "CAP_NET_ADMIN",
		},
		{
			name: "all capabilities",
			compose: `services:
  api:
    cap_add: [ALL]
`,
			ruleID:   RuleCapAddALL,
			service:  "api",
			evidence: "ALL",
		},
		{
			name: "unconfined seccomp",
			compose: `services:
  api:
    security_opt:
      - seccomp=unconfined
`,
			ruleID:   RuleSeccompUnconfined,
			service:  "api",
			evidence: "seccomp=unconfined",
		},
		{
			name: "unconfined apparmor",
			compose: `services:
  api:
    security_opt: [apparmor=unconfined]
`,
			ruleID:   RuleAppArmorUnconfined,
			service:  "api",
			evidence: "apparmor=unconfined",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := Audit([]byte(tt.compose), "compose.yaml")
			if err != nil {
				t.Fatalf("Audit() error = %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("Audit() returned %d findings, want 1: %#v", len(findings), findings)
			}
			finding := findings[0]
			if finding.RuleID != tt.ruleID {
				t.Errorf("RuleID = %q, want %q", finding.RuleID, tt.ruleID)
			}
			if finding.Service != tt.service {
				t.Errorf("Service = %q, want %q", finding.Service, tt.service)
			}
			if finding.Filename != "compose.yaml" || finding.File != "compose.yaml" {
				t.Errorf("filename fields = %q/%q, want compose.yaml", finding.Filename, finding.File)
			}
			if finding.Source == "" || finding.SourceRef != finding.Source {
				t.Errorf("source fields = %q/%q, want a matching source reference", finding.Source, finding.SourceRef)
			}
			if finding.Line == 0 || finding.Column == 0 {
				t.Errorf("location = %d:%d, want a source location", finding.Line, finding.Column)
			}
			if finding.Severity == "" || finding.Explanation == "" || finding.Remediation == "" {
				t.Errorf("incomplete finding metadata: %#v", finding)
			}
			if tt.evidence != "" && !strings.Contains(finding.Evidence, tt.evidence) {
				t.Errorf("Evidence = %q, want it to contain %q", finding.Evidence, tt.evidence)
			}
		})
	}
}

func TestAuditSafeConfig(t *testing.T) {
	compose := `services:
  api:
    image: example/api:latest
    privileged: false
    network_mode: bridge
    pid: private
    ipc: private
    volumes:
      - app-data:/var/lib/app
      - ./src:/app/src
    cap_add: [NET_RAW]
    security_opt: [label=disable, seccomp=default]
volumes:
  app-data:
`

	findings, err := Audit([]byte(compose), "safe.yaml")
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("Audit() returned findings for a safe config: %#v", findings)
	}
}

func TestAuditLocations(t *testing.T) {
	compose := "services:\n  api:\n    image: example/api\n    privileged: true\n"
	findings, err := Audit([]byte(compose), "locations.yaml")
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("Audit() returned %d findings, want 1", len(findings))
	}
	if got, want := findings[0].Line, 4; got != want {
		t.Errorf("Line = %d, want %d", got, want)
	}
	if got, want := findings[0].Column, 5; got != want {
		t.Errorf("Column = %d, want %d", got, want)
	}
}

func TestAuditMergedServiceValues(t *testing.T) {
	compose := `x-security: &security
  privileged: true
services:
  api:
    <<: *security
`
	findings, err := Audit([]byte(compose), "merged.yaml")
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 1 || findings[0].RuleID != RulePrivileged {
		t.Fatalf("Audit() findings = %#v, want one privileged finding", findings)
	}
}

func TestAuditMalformedYAML(t *testing.T) {
	for _, input := range []string{
		"services:\n  api: [\n",
		"services:\n  api:\n    privileged: true\n---\nservices: {}\n",
	} {
		if _, err := Audit([]byte(input), "broken.yaml"); err == nil {
			t.Errorf("Audit(%q) error = nil, want malformed or multi-document error", input)
		}
	}
}

func TestAuditMissingAndOddServicesDoNotPanic(t *testing.T) {
	tests := []string{
		"version: '3.9'\n",
		"services: null\n",
		"services: []\n",
		`services:
  null: true
  bad: null
  list: []
  odd:
    privileged: "true"
    network_mode: [host]
    pid: 1
    ipc: null
    volumes: [null, 1, {source: /etc}]
    cap_add: {name: SYS_ADMIN}
    security_opt: {seccomp: unconfined}
`,
	}

	for _, input := range tests {
		findings, err := Audit([]byte(input), "odd.yaml")
		if err != nil {
			// Duplicate or otherwise invalid service shapes may be rejected by
			// the YAML parser; the important contract here is no panic.
			continue
		}
		if findings == nil {
			t.Errorf("Audit(%q) returned nil findings; want a safe empty result", input)
		}
	}
}

func TestAuditDuplicateKeysReturnsError(t *testing.T) {
	input := `services:
  api:
    privileged: true
    privileged: false
`
	if _, err := Audit([]byte(input), "duplicate.yaml"); err == nil {
		t.Fatal("Audit() error = nil, want duplicate-key error")
	}
}

func TestAuditUntrustedStrings(t *testing.T) {
	serviceName := `<script>alert("x")</script>`
	compose := `services:
  '<script>alert("x")</script>':
    privileged: true
    volumes:
      - "/etc/<img src=x onerror=alert(1)>:/target"
`
	findings, err := Audit([]byte(compose), "untrusted.yaml")
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("Audit() returned %d findings, want privileged and sensitive mount", len(findings))
	}
	for _, finding := range findings {
		if finding.Service != serviceName {
			t.Errorf("Service = %q, want %q", finding.Service, serviceName)
		}
		if finding.Explanation == "" || finding.Remediation == "" {
			t.Errorf("finding lost text metadata: %#v", finding)
		}
	}
}

func TestLoadFileAndVisitServices(t *testing.T) {
	directory := t.TempDir()
	filename := filepath.Join(directory, "compose.yaml")
	input := []byte("services:\n  first:\n    image: one\n  second:\n    image: two\n")
	if err := os.WriteFile(filename, input, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	document, err := LoadFile(filename)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if document.Filename != filename {
		t.Errorf("Filename = %q, want %q", document.Filename, filename)
	}
	var names []string
	document.VisitServices(func(service Service) { names = append(names, service.Name) })
	if got, want := strings.Join(names, ","), "first,second"; got != want {
		t.Errorf("visited services = %q, want %q", got, want)
	}
}
