import {
  useMemo,
  useRef,
  useState,
  useCallback,
  useEffect,
  type KeyboardEvent,
} from 'react';
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowDownToLine,
  ArrowRight,
  BookOpen,
  Braces,
  Check,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Clock3,
  Code2,
  FileCode2,
  FileInput,
  Fingerprint,
  Info,
  LockKeyhole,
  Play,
  RotateCcw,
  ShieldCheck,
  ShieldAlert,
  Upload,
  X,
} from 'lucide-react';
import {
  analyzeSource,
  RULES,
  type AuditReport,
  type Finding,
  type Severity,
} from './lib/analyzer';

const SAMPLE_SOURCE = `import express from 'express';

const app = express();
app.use(express.json());

app.post('/preview', (req, res) => {
  const userInput = req.body.expression;

  // Dynamic evaluation of request data
  const result = eval(userInput);

  const page = document.querySelector('#preview');
  page.innerHTML = req.body.markup;

  res.send({ result });
});

const serviceToken = 'sk_live_7gP9xL2mQ4vR8wT1'; // Synthetic value for this example only.

app.listen(3000);`;

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const severityMeta: Record<
  Severity,
  { label: string; icon: typeof AlertTriangle }
> = {
  critical: { label: 'Critical', icon: ShieldAlert },
  high: { label: 'High', icon: AlertTriangle },
  medium: { label: 'Medium', icon: AlertCircle },
  low: { label: 'Low', icon: Check },
  info: { label: 'Info', icon: Info },
};

function displayFileName(name: string) {
  return name || 'untitled.js';
}

function App() {
  const [source, setSource] = useState('');
  const [fileName, setFileName] = useState('untitled.js');
  const [report, setReport] = useState<AuditReport | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [runError, setRunError] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [ruleFilter, setRuleFilter] = useState('all');
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(
    new Set(),
  );
  const [rulesOpen, setRulesOpen] = useState(false);
  const [highlightedLine, setHighlightedLine] = useState<number | null>(null);
  const [notice, setNotice] = useState('');
  const sourceRef = useRef<HTMLTextAreaElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const runTimerRef = useRef<number | undefined>(undefined);
  const noticeTimerRef = useRef<number | undefined>(undefined);

  useEffect(
    () => () => {
      window.clearTimeout(runTimerRef.current);
      window.clearTimeout(noticeTimerRef.current);
    },
    [],
  );

  const lineCount = Math.max(1, source.split('\n').length);
  const sourceLines = source.split('\n');
  const lineDigits = String(lineCount).length;
  const visibleFindings = useMemo(() => {
    if (!report) return [];
    return report.findings.filter((finding) => {
      const severityMatches =
        severityFilter === 'all' || finding.severity === severityFilter;
      const ruleMatches = ruleFilter === 'all' || finding.ruleId === ruleFilter;
      return severityMatches && ruleMatches;
    });
  }, [report, severityFilter, ruleFilter]);

  const showNotice = useCallback((message: string) => {
    setNotice(message);
    window.clearTimeout(noticeTimerRef.current);
    noticeTimerRef.current = window.setTimeout(() => setNotice(''), 2600);
  }, []);

  const setNewSource = useCallback((text: string, name: string) => {
    setSource(text);
    setFileName(displayFileName(name));
    setReport(null);
    setRunError('');
    setExpandedFindings(new Set());
    setHighlightedLine(null);
  }, []);

  const runAudit = useCallback(() => {
    if (!source.trim()) {
      setReport(null);
      setRunError('');
      showNotice('Add source code before running an audit.');
      sourceRef.current?.focus();
      return;
    }
    if (isRunning) return;
    setIsRunning(true);
    setReport(null);
    setRunError('');
    setExpandedFindings(new Set());

    // The analyzer is local and synchronous; this short pause makes the run state
    // legible without moving source or results off this device.
    runTimerRef.current = window.setTimeout(() => {
      try {
        setReport(analyzeSource(source, fileName));
      } catch (error) {
        setRunError(
          error instanceof Error
            ? error.message
            : 'The analyzer could not complete this run.',
        );
      } finally {
        setIsRunning(false);
      }
    }, 160);
  }, [fileName, isRunning, showNotice, source]);

  const loadSample = useCallback(() => {
    setNewSource(SAMPLE_SOURCE, 'vulnerable-example.ts');
    showNotice('Example source loaded. Run the local audit when ready.');
  }, [setNewSource, showNotice]);

  const importFile = useCallback(
    async (file?: File) => {
      if (!file) return;
      try {
        const text = await file.text();
        setNewSource(text, file.name);
        showNotice(`Loaded ${file.name} locally.`);
      } catch {
        showNotice(
          'Could not read that file. Choose a text-based source file.',
        );
      }
      if (fileRef.current) fileRef.current.value = '';
    },
    [setNewSource, showNotice],
  );

  const exportReport = useCallback(() => {
    if (!report) return;
    const payload = {
      tool: 'TraceGuard',
      fileName,
      report,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `traceguard-${fileName.replace(/\.[^.]+$/, '')}-report.json`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    showNotice('JSON report exported.');
  }, [fileName, report, showNotice]);

  const jumpToFinding = useCallback(
    (finding: Finding) => {
      const editor = sourceRef.current;
      if (!editor) return;
      const lines = source.split('\n');
      const targetLine = Math.min(Math.max(finding.line, 1), lines.length);
      const start = lines
        .slice(0, targetLine - 1)
        .reduce((total, line) => total + line.length + 1, 0);
      const end = start + (lines[targetLine - 1]?.length ?? 0);
      editor.focus();
      editor.setSelectionRange(start, end);
      editor.scrollTop = Math.max(0, (targetLine - 1) * 20 - 90);
      setHighlightedLine(targetLine);
      window.setTimeout(() => setHighlightedLine(null), 1600);
    },
    [source],
  );

  const toggleFinding = (id: string) => {
    setExpandedFindings((previous) => {
      const next = new Set(previous);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleEditorKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') {
      event.preventDefault();
      runAudit();
      return;
    }
    if (event.key === 'Tab') {
      event.preventDefault();
      const textarea = event.currentTarget;
      const start = textarea.selectionStart;
      const end = textarea.selectionEnd;
      const nextSource = `${source.slice(0, start)}  ${source.slice(end)}`;
      setSource(nextSource);
      setReport(null);
      requestAnimationFrame(() =>
        textarea.setSelectionRange(start + 2, start + 2),
      );
    }
  };

  const clearSource = () => {
    setNewSource('', 'untitled.js');
    sourceRef.current?.focus();
  };

  const reportHasParseErrors = Boolean(report?.parseErrors.length);
  const hasCompletedReport = Boolean(report);

  return (
    <main className="workbench">
      <header className="topbar">
        <div className="brand-lockup" aria-label="TraceGuard">
          <div className="brand-mark">
            <Fingerprint size={19} strokeWidth={1.8} />
          </div>
          <div>
            <div className="brand-name">TraceGuard</div>
            <div className="brand-subtitle">Source security workbench</div>
          </div>
        </div>
        <div className="topbar-right">
          <div
            className="privacy-pill"
            data-testid="status-local-only"
            title="Your source stays in this browser"
          >
            <LockKeyhole size={12} />
            <span>LOCAL ONLY · NO UPLOADS</span>
          </div>
        </div>
      </header>

      <div className="workbench-content">
        <section className="page-intro" aria-labelledby="page-title">
          <div>
            <div className="eyebrow">Source security check</div>
            <h1 className="page-title" id="page-title">
              Check code for security issues.
            </h1>
            <p className="page-copy">
              Paste or open code you are allowed to review. TraceGuard checks it
              in this browser and shows the lines to review.
            </p>
          </div>
          <div className="header-meta" data-testid="status-analyzer-local">
            <span className="status-led" />
            <span>ANALYZER READY</span>
            <span aria-hidden="true">/</span>
            <span>{RULES.length} RULES</span>
          </div>
        </section>

        <section className="workspace" aria-label="Code audit workspace">
          <section className="editor-pane" aria-labelledby="editor-heading">
            <div className="panel-heading">
              <div className="panel-title" id="editor-heading">
                <Code2 size={15} /> Source input
              </div>
              <div className="file-label" data-testid="text-current-file">
                <span className="file-dot" />
                <span>{fileName}</span>
              </div>
            </div>

            <div className="editor-controls">
              <div className="editor-tools">
                <label className="tool-button" htmlFor="source-file">
                  <Upload size={12} /> Open file
                  <input
                    ref={fileRef}
                    id="source-file"
                    type="file"
                    className="visually-hidden"
                    disabled={isRunning}
                    accept=".js,.jsx,.ts,.tsx,.mjs,.cjs,.txt,text/javascript,text/typescript"
                    data-testid="input-source-file"
                    onChange={(event) =>
                      void importFile(event.currentTarget.files?.[0])
                    }
                    aria-label="Open a local JavaScript or TypeScript file"
                  />
                </label>
                <button
                  className="tool-button"
                  type="button"
                  onClick={loadSample}
                  disabled={isRunning}
                  data-testid="button-load-sample"
                >
                  <Braces size={12} /> Load sample
                </button>
              </div>
              <div className="editor-tools">
                {source && (
                  <button
                    className="icon-button"
                    type="button"
                    title="Clear source"
                    aria-label="Clear source"
                    disabled={isRunning}
                    onClick={clearSource}
                    data-testid="button-clear-source"
                  >
                    <X size={14} />
                  </button>
                )}
                <span className="file-label">
                  <FileCode2 size={13} /> JS · TS · JSX
                </span>
              </div>
            </div>

            <div className="source-wrap">
              <div className="line-gutter" aria-hidden="true">
                {sourceLines.map((_, index) => (
                  <div
                    key={index}
                    data-testid={`text-line-number-${index + 1}`}
                    style={{
                      color:
                        highlightedLine === index + 1 ? '#326451' : undefined,
                    }}
                  >
                    {String(index + 1).padStart(lineDigits, ' ')}
                  </div>
                ))}
              </div>
              <textarea
                ref={sourceRef}
                className="source-input"
                value={source}
                disabled={isRunning}
                onChange={(event) => {
                  setSource(event.currentTarget.value);
                  setReport(null);
                  setRunError('');
                }}
                onKeyDown={handleEditorKeyDown}
                spellCheck={false}
                autoCapitalize="off"
                autoComplete="off"
                autoCorrect="off"
                aria-label="Source code editor"
                aria-describedby="editor-footnote"
                data-testid="input-source-code"
                placeholder={`// Paste JavaScript or TypeScript to inspect it\n// Or open a local file / load the example source`}
              />
            </div>
            <div className="editor-footer" id="editor-footnote">
              <span>
                {lineCount} {lineCount === 1 ? 'LINE' : 'LINES'} ·{' '}
                {source.length.toLocaleString()} CHARS
              </span>
              <span>⌘ / CTRL + ENTER TO RUN</span>
            </div>
            <div className="run-bar">
              <div className="run-state">
                <LockKeyhole size={12} />
                <span>
                  {isRunning
                    ? 'Analyzing in this browser…'
                    : 'Source never leaves this device'}
                </span>
              </div>
              <button
                className="run-button"
                type="button"
                onClick={runAudit}
                disabled={isRunning}
                data-testid="button-run-audit"
              >
                {isRunning ? (
                  <Activity size={14} />
                ) : (
                  <Play size={13} fill="currentColor" />
                )}
                {isRunning ? 'Analyzing…' : 'Run audit'}
                {!isRunning && <ArrowRight size={13} />}
              </button>
            </div>
          </section>

          <section className="results-pane" aria-labelledby="results-heading">
            <div className="panel-heading">
              <div className="panel-title" id="results-heading">
                <ShieldCheck size={15} /> Audit results
              </div>
              {hasCompletedReport ? (
                <div
                  className="file-label"
                  data-testid="status-report-complete"
                >
                  <Check size={12} /> COMPLETE
                </div>
              ) : (
                <div className="file-label" data-testid="status-report-idle">
                  <Clock3 size={12} /> AWAITING RUN
                </div>
              )}
            </div>

            <div className="result-summary">
              <div className="summary-top">
                <div>
                  <div className="summary-label">Security score</div>
                  <div className="score-block">
                    <span
                      className="score-number"
                      data-testid="text-security-score"
                    >
                      {report ? report.score : 'N/A'}
                    </span>
                    <span className="score-denom">/ 100</span>
                  </div>
                  <div
                    className="score-caption"
                    data-testid="text-audit-summary"
                  >
                    {report
                      ? reportHasParseErrors
                        ? 'Source could not be fully analyzed'
                        : report.findings.length
                          ? `${report.findings.length} finding${report.findings.length === 1 ? '' : 's'} · ${report.linesAnalyzed} lines analyzed`
                          : `No findings · ${report.linesAnalyzed} lines analyzed`
                      : 'Run an audit to calculate a score'}
                  </div>
                </div>
                <div className="score-mark" aria-hidden="true">
                  {reportHasParseErrors ? (
                    <AlertTriangle size={20} />
                  ) : report ? (
                    <ShieldCheck size={21} />
                  ) : (
                    <Activity size={19} />
                  )}
                </div>
              </div>
              <div
                className="severity-strip"
                aria-label="Finding totals by severity"
              >
                {SEVERITIES.map((severity) => (
                  <div
                    className={`severity-count ${severity}`}
                    key={severity}
                    data-testid={`text-total-${severity}`}
                  >
                    <strong>{report ? report.totals[severity] : 'N/A'}</strong>
                    <span>{severityMeta[severity].label}</span>
                  </div>
                ))}
              </div>
            </div>

            {report && (
              <div className="filter-row">
                <label className="visually-hidden" htmlFor="severity-filter">
                  Filter by severity
                </label>
                <select
                  className="filter-select"
                  id="severity-filter"
                  value={severityFilter}
                  onChange={(event) =>
                    setSeverityFilter(event.currentTarget.value)
                  }
                  data-testid="select-severity-filter"
                >
                  <option value="all">All severities</option>
                  {SEVERITIES.map((severity) => (
                    <option key={severity} value={severity}>
                      {severityMeta[severity].label}
                    </option>
                  ))}
                </select>
                <label className="visually-hidden" htmlFor="rule-filter">
                  Filter by rule
                </label>
                <select
                  className="filter-select"
                  id="rule-filter"
                  value={ruleFilter}
                  onChange={(event) => setRuleFilter(event.currentTarget.value)}
                  data-testid="select-rule-filter"
                >
                  <option value="all">All rules</option>
                  {RULES.map((rule) => (
                    <option key={rule.id} value={rule.id}>
                      {rule.id} · {rule.title}
                    </option>
                  ))}
                </select>
                <span className="filter-caption">
                  {visibleFindings.length} SHOWN
                </span>
                <button
                  className="tool-button export-button"
                  type="button"
                  onClick={exportReport}
                  data-testid="button-export-report"
                  aria-label="Export report as JSON"
                >
                  <ArrowDownToLine size={12} />
                  <span>JSON</span>
                </button>
              </div>
            )}

            <div className="findings-list" aria-live="polite">
              {isRunning ? (
                <div
                  className="loading-skeleton"
                  role="status"
                  aria-label="Analyzing source"
                >
                  <div className="skeleton-row" />
                  <div className="skeleton-row" />
                  <div className="skeleton-row" />
                  <div className="eyebrow">
                    Reading source against local rules…
                  </div>
                </div>
              ) : runError ? (
                <div
                  className="parse-error-panel"
                  role="alert"
                  data-testid="status-analyzer-error"
                >
                  <div className="parse-error-heading">
                    <AlertTriangle size={14} /> Analysis did not complete
                  </div>
                  <p className="detail-copy">{runError}</p>
                  <button
                    type="button"
                    className="text-action"
                    onClick={runAudit}
                    data-testid="button-retry-audit"
                  >
                    <RotateCcw size={12} /> Try again
                  </button>
                </div>
              ) : reportHasParseErrors ? (
                <div
                  className="parse-error-panel"
                  role="alert"
                  data-testid="status-parse-error"
                >
                  <div className="parse-error-heading">
                    <AlertTriangle size={14} /> Parse issue
                  </div>
                  {report?.parseErrors.map((error, index) => (
                    <div
                      className="parse-error-item"
                      key={`${index}-${error}`}
                      data-testid={`text-parse-error-${index}`}
                    >
                      {error}
                    </div>
                  ))}
                  <p className="detail-copy" style={{ marginTop: 9 }}>
                    Findings below reflect only what the analyzer could inspect.
                  </p>
                </div>
              ) : report && visibleFindings.length > 0 ? (
                visibleFindings.map((finding) => (
                  <FindingCard
                    key={finding.id}
                    finding={finding}
                    expanded={expandedFindings.has(finding.id)}
                    onToggle={() => toggleFinding(finding.id)}
                    onJump={() => jumpToFinding(finding)}
                  />
                ))
              ) : report && report.findings.length > 0 ? (
                <div
                  className="empty-results"
                  data-testid="status-no-filter-matches"
                >
                  <div className="empty-icon">
                    <CircleHelp size={21} />
                  </div>
                  <h2 className="empty-title">No matches for these filters</h2>
                  <p className="empty-copy">
                    The audit returned findings, but none match the selected
                    severity and rule.
                  </p>
                  <button
                    className="empty-cta"
                    type="button"
                    onClick={() => {
                      setSeverityFilter('all');
                      setRuleFilter('all');
                    }}
                    data-testid="button-reset-filters"
                  >
                    Reset filters
                  </button>
                </div>
              ) : report ? (
                <div className="empty-results" data-testid="status-clean-scan">
                  <div className="empty-icon">
                    <ShieldCheck size={22} />
                  </div>
                  <h2 className="empty-title">No findings in this source.</h2>
                  <p className="empty-copy">
                    The local ruleset did not identify any flagged patterns in
                    the analyzed lines.
                  </p>
                  <div className="file-label" style={{ marginTop: 13 }}>
                    <Check size={12} /> {report.rulesRun} RULES RUN ·{' '}
                    {report.linesAnalyzed} LINES
                  </div>
                </div>
              ) : (
                <div
                  className="empty-results"
                  data-testid="status-empty-results"
                >
                  <div className="empty-icon">
                    <FileInput size={21} />
                  </div>
                  <h2 className="empty-title">No code yet</h2>
                  <p className="empty-copy">
                    Paste JavaScript or TypeScript, or open a local file. Select
                    Run audit to check it.
                  </p>
                  <button
                    className="empty-cta"
                    type="button"
                    onClick={loadSample}
                    data-testid="button-empty-load-sample"
                  >
                    Load example <ArrowRight size={11} />
                  </button>
                </div>
              )}
            </div>

            {report && (
              <div className="editor-footer" data-testid="text-report-metadata">
                <span>{report.rulesRun} RULES EXECUTED</span>
                <span>
                  {report.linesAnalyzed} LINES · {report.findings.length}{' '}
                  FINDINGS
                </span>
              </div>
            )}
          </section>
        </section>

        <section className="rules-drawer" aria-label="Analyzer rule reference">
          <button
            className="rules-toggle"
            type="button"
            onClick={() => setRulesOpen((open) => !open)}
            aria-expanded={rulesOpen}
            data-testid="button-toggle-rules"
          >
            <span className="section-title">
              <BookOpen size={14} />{' '}
              <span style={{ marginLeft: 8 }}>Rule reference</span>{' '}
              <span className="file-label" style={{ marginLeft: 10 }}>
                {RULES.length} local checks
              </span>
            </span>
            {rulesOpen ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
          </button>
          {rulesOpen && (
            <div className="rules-list" data-testid="list-rule-reference">
              {RULES.map((rule) => (
                <article
                  className="rule-item"
                  key={rule.id}
                  data-testid={`rule-reference-${rule.id}`}
                >
                  <div className="rule-item-head">
                    <div className="rule-code">
                      <span className={`severity-badge ${rule.severity}`}>
                        {rule.severity}
                      </span>{' '}
                      <span style={{ marginLeft: 6 }}>{rule.id}</span>
                    </div>
                    {rule.cwe && <span className="cwe-tag">{rule.cwe}</span>}
                  </div>
                  <div className="rule-item-title" style={{ marginTop: 7 }}>
                    {rule.title}
                  </div>
                  <div className="rule-description">{rule.description}</div>
                  <div className="rule-description">
                    <strong>Recommendation:</strong> {rule.recommendation}
                  </div>
                </article>
              ))}
            </div>
          )}
        </section>

        <footer className="workbench-footer">
          <div className="footer-left">
            <span className="foot-mark">TG</span>
            <span>TraceGuard local analysis</span>
          </div>
          <div className="footer-right">
            <span>NO NETWORK REQUESTS</span>
            <span aria-hidden="true">·</span>
            <span>NO SOURCE PERSISTENCE</span>
          </div>
        </footer>
      </div>

      {notice && (
        <div className="toast-message" role="status" data-testid="status-toast">
          {notice}
        </div>
      )}
    </main>
  );
}

function FindingCard({
  finding,
  expanded,
  onToggle,
  onJump,
}: {
  finding: Finding;
  expanded: boolean;
  onToggle: () => void;
  onJump: () => void;
}) {
  const severity = finding.severity;
  return (
    <article
      className={`finding-card sev-${severity}`}
      data-testid={`finding-${finding.id}`}
    >
      <div className="finding-main">
        <div className="finding-top">
          <div className="finding-badges">
            <span
              className={`severity-badge ${severity}`}
              data-testid={`text-finding-severity-${finding.id}`}
            >
              {severity}
            </span>
            <span
              className="rule-code"
              data-testid={`text-finding-rule-${finding.id}`}
            >
              {finding.ruleId}
            </span>
          </div>
          <button
            className="finding-location text-action"
            type="button"
            onClick={onJump}
            aria-label={`Jump to line ${finding.line}, column ${finding.column}`}
            data-testid={`button-jump-to-finding-${finding.id}`}
          >
            <Code2 size={11} /> L{finding.line}:C{finding.column}
          </button>
        </div>
        <h3
          className="finding-title"
          data-testid={`text-finding-title-${finding.id}`}
        >
          {finding.title}
        </h3>
        <p className="finding-description">{finding.description}</p>
        <div className="finding-actions">
          <button
            className="text-action"
            type="button"
            onClick={onToggle}
            aria-expanded={expanded}
            data-testid={`button-toggle-detail-${finding.id}`}
          >
            {expanded ? 'Hide details' : 'Inspect finding'}{' '}
            {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
          </button>
          <span
            className="confidence"
            data-testid={`text-finding-confidence-${finding.id}`}
          >
            {Math.round(finding.confidence * 100)}% CONFIDENCE
          </span>
        </div>
      </div>
      {expanded && (
        <div
          className="finding-detail"
          data-testid={`detail-finding-${finding.id}`}
        >
          {finding.evidence && (
            <div className="detail-block">
              <div className="detail-label">Evidence</div>
              <div className="evidence-box">{finding.evidence}</div>
            </div>
          )}
          <div className="detail-block">
            <div className="detail-label">Why it matters</div>
            <div className="detail-copy">{finding.description}</div>
          </div>
          <div className="detail-block">
            <div className="detail-label">Recommended action</div>
            <div className="detail-copy">{finding.recommendation}</div>
          </div>
          <div
            className="detail-block"
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}
          >
            <div>
              <div className="detail-label">Category</div>
              <div className="detail-copy">{finding.category}</div>
            </div>
            {finding.cwe && <span className="cwe-tag">{finding.cwe}</span>}
          </div>
        </div>
      )}
    </article>
  );
}

export default App;
