package report

const reportHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}}</title>
  <style>
    :root {
      color-scheme: light;
      --ink: #182230;
      --muted: #627083;
      --line: #dbe3ec;
      --canvas: #f4f7fb;
      --panel: #ffffff;
      --navy: #12243a;
      --blue: #246bce;
      --high: #b93829;
      --critical: #7f1d1d;
      --medium: #9a6700;
      --low: #2e6f49;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--canvas);
      color: var(--ink);
      font: 15px/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    .shell { max-width: 1180px; margin: 0 auto; padding: 28px 20px 56px; }
    header {
      background: linear-gradient(135deg, var(--navy), #1e4269);
      color: white;
      border-radius: 18px;
      padding: 28px 30px;
      box-shadow: 0 12px 30px rgba(18, 36, 58, .14);
    }
    header h1 { margin: 0 0 4px; font-size: clamp(1.7rem, 3vw, 2.35rem); letter-spacing: -.02em; }
    header p { margin: 0; color: #dbeafe; max-width: 780px; }
    .eyebrow { text-transform: uppercase; letter-spacing: .12em; font-size: .75rem; font-weight: 700; color: #9ec5f7; }
    .grid { display: grid; gap: 16px; }
    .metrics { grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); margin: 18px 0; }
    .two-column { grid-template-columns: minmax(0, 1.45fr) minmax(280px, .8fr); }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 20px;
      box-shadow: 0 5px 15px rgba(18, 36, 58, .04);
    }
    .metric strong { display: block; font-size: 1.75rem; color: var(--navy); }
    .metric span, .muted { color: var(--muted); }
    h2 { margin: 0 0 14px; font-size: 1.2rem; }
    h3 { margin: 0 0 6px; font-size: 1rem; }
    .finding, .event, .warning { border-top: 1px solid var(--line); padding: 15px 0; }
    .finding:first-child, .event:first-child, .warning:first-child { border-top: 0; padding-top: 0; }
    .finding:last-child, .event:last-child, .warning:last-child { padding-bottom: 0; }
    .finding-head, .event-head, .source-head { display: flex; gap: 10px; align-items: baseline; justify-content: space-between; flex-wrap: wrap; }
    .badge { display: inline-block; border-radius: 999px; padding: 2px 9px; font-size: .72rem; font-weight: 800; letter-spacing: .04em; text-transform: uppercase; }
    .badge.high { background: #fee2e2; color: var(--high); }
    .badge.critical { background: #fce7f3; color: var(--critical); }
    .badge.medium { background: #fef3c7; color: var(--medium); }
    .badge.low { background: #dcfce7; color: var(--low); }
    .badge.neutral { background: #e8eef6; color: #4b5c70; }
    .location, code { color: #31577e; font: .86em ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .evidence { margin-top: 10px; border-left: 3px solid #b9d2f3; padding-left: 12px; }
    .evidence pre { white-space: pre-wrap; overflow-wrap: anywhere; margin: 5px 0 0; color: #39485a; font: .85em/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .timeline { position: relative; }
    .event-dot { width: 9px; height: 9px; border-radius: 50%; background: var(--blue); display: inline-block; margin-right: 7px; }
    .event time { color: var(--muted); font: .83em ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .event p { margin: 4px 0 0 16px; color: #46566a; }
    .empty { color: var(--muted); margin: 0; }
    table { width: 100%; border-collapse: collapse; }
    th, td { text-align: left; vertical-align: top; border-top: 1px solid var(--line); padding: 10px 8px; }
    th { color: var(--muted); font-size: .8rem; text-transform: uppercase; letter-spacing: .06em; }
    td:first-child, th:first-child { padding-left: 0; }
    td:last-child, th:last-child { padding-right: 0; }
    .hash { word-break: break-all; }
    .footnote { color: var(--muted); font-size: .85rem; margin-top: 18px; }
    @media (max-width: 760px) { .two-column { grid-template-columns: 1fr; } .shell { padding: 16px 12px 40px; } header { padding: 22px; } }
  </style>
</head>
<body>
  <main class="shell">
    <header>
      <div class="eyebrow">CAIRN · offline evidence report</div>
      <h1>{{.Title}}</h1>
      <p>Deterministic analysis of Linux authentication activity and Docker Compose security posture. Every finding below is backed by local source evidence.</p>
    </header>

    <section class="grid metrics" aria-label="Summary metrics">
      <div class="panel metric"><span>Events</span><strong>{{.Summary.Events}}</strong></div>
      <div class="panel metric"><span>SSH failures</span><strong>{{.Summary.FailedAuthentications}}</strong></div>
      <div class="panel metric"><span>Successful logins</span><strong>{{.Summary.SuccessfulLogins}}</strong></div>
      <div class="panel metric"><span>Privilege events</span><strong>{{.Summary.PrivilegeEvents}}</strong></div>
      <div class="panel metric"><span>Findings</span><strong>{{.Summary.AuthenticationFindings}} + {{.Summary.ComposeFindings}}</strong><span>auth + Compose</span></div>
      <div class="panel metric"><span>Highest severity</span><strong>{{.Summary.HighestSeverity}}</strong></div>
    </section>

    <section class="grid two-column">
      <div class="panel">
        <h2>Authentication findings</h2>
        {{if .AuthFindings}}
          {{range .AuthFindings}}
          <article class="finding">
            <div class="finding-head">
              <h3>{{ruleLabel .Rule}}</h3>
              <span class="badge {{severityClass .Severity}}">{{.Severity}}</span>
            </div>
            <div class="location">{{findingLocation .}}</div>
            <p>{{.Message}}</p>
            {{if .SourceIP}}<p class="muted">Source: <code>{{.SourceIP}}</code>{{if .User}} · User: <code>{{.User}}</code>{{end}}</p>{{end}}
            <div class="evidence">
              <strong>Evidence</strong>
              {{range .Evidence}}<div class="location">{{evidenceLocation .}}</div><pre>{{.Raw}}</pre>{{end}}
            </div>
            {{if eq .Rule "brute_force"}}<p><strong>Remediation:</strong> rate-limit or disable password authentication, review the affected account, and restrict SSH access to trusted sources.</p>{{else if eq .Rule "success_after_failures"}}<p><strong>Remediation:</strong> verify the login with the account owner, rotate credentials if unexpected, and review the host for follow-on activity.</p>{{else}}<p><strong>Remediation:</strong> verify the administrative action, review sudo policy, and remove unnecessary root access.</p>{{end}}
          </article>
          {{end}}
        {{else}}<p class="empty">No deterministic authentication findings were produced.</p>{{end}}
      </div>

      <div class="panel">
        <h2>Docker Compose audit</h2>
        {{if .ComposeFindings}}
          {{range .ComposeFindings}}
          <article class="finding">
            <div class="finding-head">
              <h3>{{.RuleID}} · {{.Service}}</h3>
              <span class="badge {{severityClass .Severity}}">{{.Severity}}</span>
            </div>
            <div class="location">{{composeLocation .}}</div>
            <p>{{.Explanation}}</p>
            <div class="evidence"><strong>Configuration:</strong> <code>{{.Evidence}}</code></div>
            <p><strong>Remediation:</strong> {{.Remediation}}</p>
          </article>
          {{end}}
        {{else}}<p class="empty">No focused Docker Compose risks were found.</p>{{end}}
      </div>
    </section>

    <section class="panel" style="margin-top: 16px">
      <h2>Chronological incident timeline</h2>
      {{if .Timeline}}
        <div class="timeline">
        {{range .Timeline}}
          <article class="event">
            <div class="event-head"><h3><span class="event-dot"></span>{{eventLabel .}}</h3><time>{{formatTime .Timestamp}}</time></div>
            <div class="location">{{evidenceLocation .}}</div>
            <p>{{if .User}}User <code>{{.User}}</code>{{end}}{{if .SourceIP}} from <code>{{.SourceIP}}</code>{{end}}{{if .TargetUser}} targeting <code>{{.TargetUser}}</code>{{end}}{{if .Command}} · command <code>{{.Command}}</code>{{end}}</p>
            <div class="evidence"><pre>{{.Raw}}</pre></div>
          </article>
        {{end}}
        </div>
      {{else}}<p class="empty">No supported authentication events were found.</p>{{end}}
    </section>

    <section class="panel" style="margin-top: 16px">
      <h2>Analyzed evidence</h2>
      {{if .Sources}}
      <table>
        <thead><tr><th>Source</th><th>Type</th><th>Bytes</th><th>SHA-256</th></tr></thead>
        <tbody>{{range .Sources}}<tr><td><code>{{.Name}}</code></td><td>{{.Kind}}</td><td>{{.Bytes}}</td><td class="hash"><code>{{.SHA256}}</code></td></tr>{{end}}</tbody>
      </table>
      {{else}}<p class="empty">No supported source files were read.</p>{{end}}
    </section>

    <section class="panel" style="margin-top: 16px">
      <h2>Parser and input warnings</h2>
      {{if .Warnings}}
        {{range .Warnings}}<div class="warning"><strong>{{.Kind}}</strong> <span class="location">{{.SourceFile}}{{if .Line}}:{{.Line}}{{end}}</span><div>{{.Message}}</div></div>{{end}}
      {{else}}<p class="empty">No parser or input warnings.</p>{{end}}
      <p class="footnote">CAIRN is a deterministic triage aid. A finding is not proof of compromise, and absence of a finding is not proof of safety.</p>
    </section>
  </main>
</body>
</html>
`
