import assert from 'node:assert/strict';
import test from 'node:test';

import { analyzeProject, analyzeSource } from '../src/lib/analyzer.ts';

function ruleIds(source, fileName = 'sample.ts') {
  return analyzeSource(source, fileName).findings.map(
    (finding) => finding.ruleId,
  );
}

test('parses real TypeScript and reports dynamic code with source positions', () => {
  const report = analyzeSource(
    'const first = 1;\neval(input);\nconst second = new Function("return 1");',
  );

  assert.deepEqual(
    report.findings.map(({ ruleId, line }) => [ruleId, line]),
    [
      ['TG001', 2],
      ['TG002', 3],
    ],
  );
  assert.equal(report.totals.high, 2);
  assert.equal(report.linesAnalyzed, 3);
});

test('tracks browser and request input into HTML sinks without flagging text output', () => {
  const source = `
const q = new URLSearchParams(window.location.search).get("q");
const copied = q;
element.innerHTML = copied;
document.write(req.query.message);
element.outerHTML = document.cookie;
document.querySelector("#safe").textContent = req.query.name;
`;
  const report = analyzeSource(source, 'page.js');

  assert.deepEqual(
    report.findings.map((finding) => finding.ruleId),
    ['TG003', 'TG003', 'TG003'],
  );
  assert.deepEqual(
    report.findings.map((finding) => finding.line),
    [4, 5, 6],
  );
});

test('parses TSX and detects tainted React HTML injection', () => {
  const source = `
const markup = req.body.markup;
const preview = <div dangerouslySetInnerHTML={{ __html: markup }} />;
`;
  const report = analyzeSource(source, 'preview.tsx');
  assert.deepEqual(
    report.findings.map((finding) => finding.ruleId),
    ['TG003'],
  );
  assert.equal(report.parseErrors.length, 0);
});

test('distinguishes interpolated SQL input from bound query parameters', () => {
  const source = `
const id = req.params.id;
db.query("select * from users where id = " + id);
db.query("select * from users where id = $1", [id]);
`;
  assert.deepEqual(ruleIds(source), ['TG004']);
});

test('resolves aliased child_process imports and flags a tainted shell command', () => {
  const source = `
import { exec as run } from "node:child_process";
const command = req.query.command;
run(\`ping \${command}\`);
`;
  const report = analyzeSource(source, 'route.ts');
  assert.deepEqual(
    report.findings.map((finding) => finding.ruleId),
    ['TG005'],
  );
  assert.equal(report.findings[0].severity, 'high');
  assert.equal(report.findings[0].filePath, 'route.ts');
});

test('treats a fixed shell call as a review warning rather than proven injection', () => {
  const report = analyzeSource(
    'import { exec } from "node:child_process";\nexec("uptime");',
    'fixed-command.ts',
  );
  assert.equal(report.findings.length, 1);
  assert.equal(report.findings[0].severity, 'medium');
  assert.equal(report.findings[0].confidence, 0.63);
});

test('identifies credential-shaped literals but ignores explicit placeholders', () => {
  const source = `
const API_KEY = "sk_live_abcdefghijk_123456";
const clientSecret = "replace-me-with-a-secret";
`;
  assert.deepEqual(ruleIds(source), ['TG006']);
});

test('detects disabled TLS, weak hashes, credentialed wildcard CORS, weak token randomness, and unsigned JWT config', () => {
  const source = `
const options = { rejectUnauthorized: false };
const digest = crypto.createHash("md5");
const corsOptions = cors({ origin: "*", credentials: true });
const sessionToken = Math.random();
verify(token, key, { algorithms: ["none"] });
`;
  assert.deepEqual(ruleIds(source), [
    'TG007',
    'TG008',
    'TG009',
    'TG010',
    'TG011',
  ]);
});

test('does not report safe examples, comments, or unrelated names', () => {
  const source = `
// eval(userInput) is only text inside this comment
const requestedValue = location.search;
target.textContent = requestedValue;
const digest = crypto.createHash("sha256");
const randomSample = Math.random();
`;
  assert.deepEqual(ruleIds(source), []);
});

test('reports syntax errors instead of silently treating malformed source as clean', () => {
  const report = analyzeSource('const answer = ;', 'broken.ts');
  assert.ok(report.parseErrors.length > 0);
  assert.match(report.parseErrors[0], /Line 1/);
});

test('enforces a source-size limit with an explicit error', () => {
  const report = analyzeSource('x'.repeat(500_001));
  assert.equal(report.findings.length, 0);
  assert.equal(report.parseErrors.length, 1);
  assert.match(report.parseErrors[0], /too large/);
});

test('aggregates findings from separate local files with file paths intact', () => {
  const report = analyzeProject([
    { fileName: 'one.ts', source: 'eval(input)' },
    { fileName: 'two.js', source: 'crypto.createHash("md5")' },
  ]);

  assert.equal(report.filesAnalyzed, 2);
  assert.equal(report.findings.length, 2);
  assert.deepEqual(
    report.findings.map((finding) => finding.filePath),
    ['one.ts', 'two.js'],
  );
});
