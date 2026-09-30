import * as ts from 'typescript';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  description: string;
  recommendation: string;
  cwe: string;
}

export interface Finding {
  id: string;
  ruleId: string;
  severity: Severity;
  category: string;
  title: string;
  description: string;
  filePath: string;
  line: number;
  column: number;
  evidence: string;
  recommendation: string;
  cwe: string;
  confidence: number;
}

export interface AuditReport {
  findings: Finding[];
  score: number;
  totals: Record<Severity, number>;
  linesAnalyzed: number;
  rulesRun: number;
  parseErrors: string[];
}

export interface SourceFileInput {
  fileName: string;
  source: string;
}

export interface ProjectAuditReport extends AuditReport {
  filesAnalyzed: number;
}

const MAX_SOURCE_CHARACTERS = 500_000;

export const RULES: Rule[] = [
  {
    id: 'TG001',
    title: 'Dynamic code execution with eval',
    severity: 'high',
    category: 'Code injection',
    description:
      'eval executes a string as program code. If that string includes user-controlled data, an attacker may execute code in the current context.',
    recommendation:
      'Remove eval. Use a fixed parser, a lookup table, or explicit control flow instead of turning strings into code.',
    cwe: 'CWE-95',
  },
  {
    id: 'TG002',
    title: 'Dynamic code construction with Function',
    severity: 'high',
    category: 'Code injection',
    description:
      'The Function constructor compiles a string into executable code and can create an injection path when its inputs are influenced by users.',
    recommendation:
      'Avoid new Function. Replace generated code with ordinary functions and validated data structures.',
    cwe: 'CWE-95',
  },
  {
    id: 'TG003',
    title: 'Untrusted data reaches an HTML sink',
    severity: 'high',
    category: 'Cross-site scripting',
    description:
      'Data from a request, URL, or browser location appears to reach an HTML-writing API. The value may be interpreted as markup or script.',
    recommendation:
      'Prefer textContent or framework text interpolation. If rich HTML is required, sanitize it with a maintained allow-list sanitizer immediately before rendering.',
    cwe: 'CWE-79',
  },
  {
    id: 'TG004',
    title: 'Possible SQL injection',
    severity: 'high',
    category: 'Injection',
    description:
      'Request-controlled data appears in a SQL query argument. String interpolation does not safely encode SQL values.',
    recommendation:
      'Use parameterized queries and bind each value separately. Do not interpolate request data into SQL text.',
    cwe: 'CWE-89',
  },
  {
    id: 'TG005',
    title: 'Possible shell command injection',
    severity: 'medium',
    category: 'Command injection',
    description:
      'Request-controlled data appears in a child_process command. Shell-based APIs interpret metacharacters as control syntax.',
    recommendation:
      'Avoid shell execution. Use execFile or spawn with a fixed executable and an argument array; validate each argument against an allow-list.',
    cwe: 'CWE-78',
  },
  {
    id: 'TG006',
    title: 'Hard-coded credential or secret',
    severity: 'high',
    category: 'Secrets management',
    description:
      'A credential-shaped variable or a recognizable secret appears as a string literal in source code. Committed secrets can be recovered from source history.',
    recommendation:
      'Revoke and rotate any real exposed credential. Load secrets from an environment or a dedicated secret manager, and keep them out of source control.',
    cwe: 'CWE-798',
  },
  {
    id: 'TG007',
    title: 'TLS certificate verification disabled',
    severity: 'high',
    category: 'Transport security',
    description:
      'The code disables certificate verification. This removes an important check against interception of encrypted connections.',
    recommendation:
      'Keep certificate verification enabled. Fix the trust store or certificate chain instead of accepting unverified certificates.',
    cwe: 'CWE-295',
  },
  {
    id: 'TG008',
    title: 'Weak hashing algorithm',
    severity: 'medium',
    category: 'Cryptography',
    description:
      'MD5 and SHA-1 are no longer suitable for collision-resistant security uses. A fast general-purpose hash is also not suitable for password storage.',
    recommendation:
      'For integrity or signatures, use SHA-256 or stronger. For passwords, use a password-hashing scheme such as Argon2id, scrypt, or bcrypt with salts and appropriate cost.',
    cwe: 'CWE-328',
  },
  {
    id: 'TG009',
    title: 'Wildcard CORS with credentials',
    severity: 'high',
    category: 'Access control',
    description:
      'A wildcard origin is combined with credentialed cross-origin requests. This configuration can expose authenticated responses to unintended sites.',
    recommendation:
      'Use a specific allow-list of trusted origins. Keep credentialed CORS disabled for origins you do not control.',
    cwe: 'CWE-942',
  },
  {
    id: 'TG010',
    title: 'Insecure randomness used for a security token',
    severity: 'medium',
    category: 'Cryptography',
    description:
      'Math.random is predictable and is not designed for security-sensitive values such as tokens, session IDs, keys, or nonces.',
    recommendation:
      'Use crypto.randomBytes or crypto.randomUUID in Node.js, or crypto.getRandomValues in the browser.',
    cwe: 'CWE-338',
  },
  {
    id: 'TG011',
    title: 'JWT accepts the none algorithm',
    severity: 'high',
    category: 'Authentication',
    description:
      'The JWT verification options permit the none algorithm, which does not provide a signature.',
    recommendation:
      'Allow-list the expected signing algorithm or algorithms and reject unsigned tokens.',
    cwe: 'CWE-347',
  },
];

const RULE_BY_ID = new Map(RULES.map((rule) => [rule.id, rule]));
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const RISK_WEIGHT: Record<Severity, number> = {
  critical: 35,
  high: 22,
  medium: 10,
  low: 4,
  info: 0,
};

interface SecretBinding {
  childProcessFunctions: Set<string>;
  childProcessNamespaces: Set<string>;
}

function scriptKindForFile(fileName: string): ts.ScriptKind {
  const extension = fileName.toLowerCase().split('.').pop();
  if (extension === 'tsx') return ts.ScriptKind.TSX;
  if (extension === 'ts' || extension === 'mts' || extension === 'cts') {
    return ts.ScriptKind.TS;
  }
  if (extension === 'jsx') return ts.ScriptKind.JSX;
  return ts.ScriptKind.JS;
}

function propertyName(
  node: ts.Expression | ts.PropertyName,
): string | undefined {
  if (
    ts.isIdentifier(node) ||
    ts.isStringLiteral(node) ||
    ts.isNumericLiteral(node)
  ) {
    return node.text;
  }
  if (ts.isComputedPropertyName(node) && ts.isStringLiteral(node.expression)) {
    return node.expression.text;
  }
  return undefined;
}

function hasRequestProperty(node: ts.Expression): boolean {
  if (!ts.isPropertyAccessExpression(node)) return false;
  const key = node.name.text;
  if (key === 'query' || key === 'body' || key === 'params') return true;
  return hasRequestProperty(node.expression);
}

function isBrowserInput(node: ts.Expression): boolean {
  if (!ts.isPropertyAccessExpression(node)) return false;
  const property = node.name.text;
  const receiver = node.expression;

  if (
    (property === 'search' || property === 'hash') &&
    ts.isIdentifier(receiver) &&
    receiver.text === 'location'
  ) {
    return true;
  }

  if (
    (property === 'search' || property === 'hash') &&
    ts.isPropertyAccessExpression(receiver) &&
    receiver.name.text === 'location' &&
    ts.isIdentifier(receiver.expression) &&
    receiver.expression.text === 'window'
  ) {
    return true;
  }

  if (
    property === 'cookie' &&
    ts.isIdentifier(receiver) &&
    receiver.text === 'document'
  ) {
    return true;
  }

  return false;
}

function isDirectTaintSource(node: ts.Expression): boolean {
  if (isBrowserInput(node) || hasRequestProperty(node)) return true;

  return (
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression) &&
    node.expression.name.text === 'get' &&
    ts.isNewExpression(node.expression.expression) &&
    ts.isIdentifier(node.expression.expression.expression) &&
    node.expression.expression.expression.text === 'URLSearchParams'
  );
}

function expressionContainsTaint(
  node: ts.Node,
  taintedIdentifiers: ReadonlySet<string>,
): boolean {
  if (ts.isIdentifier(node) && taintedIdentifiers.has(node.text)) return true;
  if (ts.isExpression(node) && isDirectTaintSource(node)) return true;

  let tainted = false;
  ts.forEachChild(node, (child) => {
    if (!tainted && expressionContainsTaint(child, taintedIdentifiers)) {
      tainted = true;
    }
  });
  return tainted;
}

function collectTaintedIdentifiers(sourceFile: ts.SourceFile): Set<string> {
  const identifiers = new Set<string>();
  let changed = true;
  let pass = 0;

  // A bounded fixed-point pass supports short alias chains without attempting
  // to claim whole-program or interprocedural data-flow analysis.
  while (changed && pass < 12) {
    changed = false;
    pass += 1;

    const visit = (node: ts.Node): void => {
      if (
        ts.isVariableDeclaration(node) &&
        ts.isIdentifier(node.name) &&
        node.initializer
      ) {
        if (
          !identifiers.has(node.name.text) &&
          expressionContainsTaint(node.initializer, identifiers)
        ) {
          identifiers.add(node.name.text);
          changed = true;
        }
      }

      if (
        ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isIdentifier(node.left) &&
        !identifiers.has(node.left.text) &&
        expressionContainsTaint(node.right, identifiers)
      ) {
        identifiers.add(node.left.text);
        changed = true;
      }

      ts.forEachChild(node, visit);
    };

    visit(sourceFile);
  }

  return identifiers;
}

function bindChildProcessImports(sourceFile: ts.SourceFile): SecretBinding {
  const childProcessFunctions = new Set<string>();
  const childProcessNamespaces = new Set<string>();

  for (const statement of sourceFile.statements) {
    if (
      ts.isImportDeclaration(statement) &&
      ts.isStringLiteral(statement.moduleSpecifier)
    ) {
      if (!/^(node:)?child_process$/.test(statement.moduleSpecifier.text))
        continue;
      const clause = statement.importClause;
      if (!clause?.namedBindings) continue;

      if (ts.isNamespaceImport(clause.namedBindings)) {
        childProcessNamespaces.add(clause.namedBindings.name.text);
      } else {
        for (const specifier of clause.namedBindings.elements) {
          const imported = specifier.propertyName?.text ?? specifier.name.text;
          if (['exec', 'execSync', 'spawn', 'spawnSync'].includes(imported)) {
            childProcessFunctions.add(specifier.name.text);
          }
        }
      }
    }

    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (
        !declaration.initializer ||
        !ts.isCallExpression(declaration.initializer) ||
        !ts.isIdentifier(declaration.initializer.expression) ||
        declaration.initializer.expression.text !== 'require' ||
        !ts.isStringLiteral(declaration.initializer.arguments[0]) ||
        !/^(node:)?child_process$/.test(
          declaration.initializer.arguments[0].text,
        )
      ) {
        continue;
      }

      if (ts.isIdentifier(declaration.name)) {
        childProcessNamespaces.add(declaration.name.text);
      } else if (ts.isObjectBindingPattern(declaration.name)) {
        for (const element of declaration.name.elements) {
          if (ts.isIdentifier(element.name)) {
            const imported = element.propertyName
              ? propertyName(element.propertyName)
              : element.name.text;
            if (
              imported &&
              ['exec', 'execSync', 'spawn', 'spawnSync'].includes(imported)
            ) {
              childProcessFunctions.add(element.name.text);
            }
          }
        }
      }
    }
  }

  return { childProcessFunctions, childProcessNamespaces };
}

function isChildProcessCall(
  node: ts.CallExpression,
  bindings: SecretBinding,
): string | undefined {
  const callee = node.expression;

  if (
    ts.isIdentifier(callee) &&
    bindings.childProcessFunctions.has(callee.text)
  ) {
    return callee.text;
  }

  if (
    ts.isPropertyAccessExpression(callee) &&
    ts.isIdentifier(callee.expression) &&
    bindings.childProcessNamespaces.has(callee.expression.text) &&
    ['exec', 'execSync', 'spawn', 'spawnSync'].includes(callee.name.text)
  ) {
    return callee.name.text;
  }

  return undefined;
}

function constantString(node: ts.Expression | undefined): string | undefined {
  if (!node) return undefined;
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node))
    return node.text;
  return undefined;
}

function isCredentialName(name: string): boolean {
  return /(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?key)/i.test(
    name,
  );
}

function looksLikeSecret(value: string): boolean {
  if (value.length < 8) return false;
  return (
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(value) ||
    /\b(?:sk_live|rk_live|ghp|github_pat|xox[baprs]|AKIA)[_-][A-Za-z0-9_-]{8,}\b/i.test(
      value,
    ) ||
    /^[A-Za-z0-9+/=_-]{28,}$/.test(value)
  );
}

function isPlaceholder(value: string): boolean {
  return /\b(?:example|placeholder|your[_-]?key|replace[_-]?me|changeme|change[_-]?this|not[_-]?real|dummy|test[_-]?only)\b/i.test(
    value,
  );
}

function propertyIsString(
  node: ts.ObjectLiteralExpression,
  name: string,
  value: string,
): boolean {
  return node.properties.some(
    (property) =>
      ts.isPropertyAssignment(property) &&
      propertyName(property.name) === name &&
      constantString(property.initializer) === value,
  );
}

function hasNoneAlgorithm(node: ts.Node): boolean {
  if (
    ts.isPropertyAssignment(node) &&
    propertyName(node.name) === 'algorithms' &&
    ts.isArrayLiteralExpression(node.initializer)
  ) {
    return node.initializer.elements.some(
      (element) =>
        constantString(element as ts.Expression)?.toLowerCase() === 'none',
    );
  }
  let result = false;
  ts.forEachChild(node, (child) => {
    if (!result && hasNoneAlgorithm(child)) result = true;
  });
  return result;
}

function getTokenContextName(node: ts.CallExpression): string | undefined {
  let current: ts.Node | undefined = node.parent;
  while (
    current &&
    !ts.isVariableDeclaration(current) &&
    !ts.isFunctionLike(current)
  ) {
    current = current.parent;
  }
  if (
    current &&
    ts.isVariableDeclaration(current) &&
    ts.isIdentifier(current.name)
  ) {
    return current.name.text;
  }
  return undefined;
}

function normalizeEvidence(value: string): string {
  const compact = value.replace(/\s+/g, ' ').trim();
  return compact.length > 200 ? `${compact.slice(0, 197)}...` : compact;
}

function makeReport(
  findings: Finding[],
  source: string,
  rulesRun: number,
  parseErrors: string[],
): AuditReport {
  const totals: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const finding of findings) totals[finding.severity] += 1;

  const deductions = findings.reduce(
    (total, finding) => total + RISK_WEIGHT[finding.severity],
    0,
  );

  return {
    findings,
    score: Math.max(0, 100 - deductions),
    totals,
    linesAnalyzed: source.length === 0 ? 0 : source.split(/\r\n|\r|\n/).length,
    rulesRun,
    parseErrors,
  };
}

export function analyzeSource(
  source: string,
  fileName = 'pasted-code.ts',
): AuditReport {
  if (source.length > MAX_SOURCE_CHARACTERS) {
    return makeReport([], '', RULES.length, [
      `Source is too large to analyze. The limit is ${MAX_SOURCE_CHARACTERS.toLocaleString()} characters.`,
    ]);
  }

  const sourceFile = ts.createSourceFile(
    fileName,
    source,
    ts.ScriptTarget.Latest,
    true,
    scriptKindForFile(fileName),
  );
  const taintedIdentifiers = collectTaintedIdentifiers(sourceFile);
  const childProcessBindings = bindChildProcessImports(sourceFile);
  const findings: Finding[] = [];
  const emitted = new Set<string>();

  const report = (
    ruleId: string,
    node: ts.Node,
    description?: string,
    confidence = 0.98,
    severityOverride?: Severity,
  ): void => {
    const rule = RULE_BY_ID.get(ruleId);
    if (!rule) return;

    const { line, character } = sourceFile.getLineAndCharacterOfPosition(
      node.getStart(sourceFile),
    );
    const id = `${ruleId}-${line + 1}-${character + 1}`;
    if (emitted.has(id)) return;
    emitted.add(id);

    findings.push({
      id,
      ruleId,
      severity: severityOverride ?? rule.severity,
      category: rule.category,
      title: rule.title,
      description: description ?? rule.description,
      filePath: fileName,
      line: line + 1,
      column: character + 1,
      evidence: normalizeEvidence(node.getText(sourceFile)),
      recommendation: rule.recommendation,
      cwe: rule.cwe,
      confidence,
    });
  };

  const visit = (node: ts.Node): void => {
    if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === 'eval'
    ) {
      report('TG001', node);
    }

    if (
      ts.isNewExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === 'Function'
    ) {
      report('TG002', node);
    }

    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken
    ) {
      const left = node.left;
      if (
        ts.isPropertyAccessExpression(left) &&
        ['innerHTML', 'outerHTML'].includes(left.name.text) &&
        expressionContainsTaint(node.right, taintedIdentifiers)
      ) {
        report('TG003', node, undefined, 0.91);
      }
    }

    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.text === 'insertAdjacentHTML' &&
      expressionContainsTaint(
        node.arguments[1] ?? node.arguments[0],
        taintedIdentifiers,
      )
    ) {
      report('TG003', node, undefined, 0.91);
    }

    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.text === 'write' &&
      ts.isIdentifier(node.expression.expression) &&
      node.expression.expression.text === 'document' &&
      node.arguments.some((argument) =>
        expressionContainsTaint(argument, taintedIdentifiers),
      )
    ) {
      report('TG003', node, undefined, 0.9);
    }

    if (
      ts.isPropertyAssignment(node) &&
      propertyName(node.name) === '__html' &&
      expressionContainsTaint(node.initializer, taintedIdentifiers)
    ) {
      report('TG003', node, undefined, 0.9);
    }

    if (ts.isCallExpression(node)) {
      const callee = node.expression;
      const callName = ts.isIdentifier(callee)
        ? callee.text
        : ts.isPropertyAccessExpression(callee)
          ? callee.name.text
          : '';

      if (
        ['query', 'execute', 'raw'].includes(callName) &&
        node.arguments[0] &&
        expressionContainsTaint(node.arguments[0], taintedIdentifiers)
      ) {
        report('TG004', node, undefined, 0.82);
      }

      const shellFunction = isChildProcessCall(node, childProcessBindings);
      if (shellFunction) {
        const taintedCommand =
          node.arguments[0] &&
          expressionContainsTaint(node.arguments[0], taintedIdentifiers);
        const usesShell =
          shellFunction === 'exec' || shellFunction === 'execSync';
        const requestsShell = node.arguments.some(
          (argument) =>
            ts.isObjectLiteralExpression(argument) &&
            argument.properties.some(
              (property) =>
                ts.isPropertyAssignment(property) &&
                propertyName(property.name) === 'shell' &&
                property.initializer.kind === ts.SyntaxKind.TrueKeyword,
            ),
        );

        if (taintedCommand) {
          report('TG005', node, undefined, 0.88, 'high');
        } else if (usesShell || requestsShell) {
          report(
            'TG005',
            node,
            'This shell-based command call receives no proven untrusted source in this file, but it still runs through a shell and needs careful argument handling.',
            0.63,
          );
        }
      }

      if (
        (callName === 'createHash' || callName === 'createHmac') &&
        ['md5', 'sha1'].includes(
          constantString(node.arguments[0])?.toLowerCase() ?? '',
        )
      ) {
        report('TG008', node, undefined, 0.96);
      }

      if (
        callName === 'random' &&
        ts.isPropertyAccessExpression(callee) &&
        ts.isIdentifier(callee.expression) &&
        callee.expression.text === 'Math'
      ) {
        const variableName = getTokenContextName(node);
        if (
          variableName &&
          /(token|secret|nonce|session|api.?key|salt)/i.test(variableName)
        ) {
          report('TG010', node, undefined, 0.9);
        }
      }

      if (callName === 'verify' && hasNoneAlgorithm(node)) {
        report('TG011', node, undefined, 0.87);
      }
    }

    if (
      ts.isVariableDeclaration(node) &&
      node.initializer &&
      ts.isIdentifier(node.name)
    ) {
      const value = constantString(node.initializer);
      if (
        value &&
        isCredentialName(node.name.text) &&
        !isPlaceholder(value) &&
        (looksLikeSecret(value) || value.length >= 12)
      ) {
        report(
          'TG006',
          node.initializer,
          undefined,
          looksLikeSecret(value) ? 0.98 : 0.74,
        );
      }
    }

    if (ts.isPropertyAssignment(node)) {
      const name = propertyName(node.name);
      const value = constantString(node.initializer);
      if (
        name &&
        value &&
        isCredentialName(name) &&
        !isPlaceholder(value) &&
        (looksLikeSecret(value) || value.length >= 12)
      ) {
        report(
          'TG006',
          node.initializer,
          undefined,
          looksLikeSecret(value) ? 0.98 : 0.74,
        );
      }

      if (
        name === 'rejectUnauthorized' &&
        node.initializer.kind === ts.SyntaxKind.FalseKeyword
      ) {
        report('TG007', node, undefined, 0.97);
      }
    }

    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isPropertyAccessExpression(node.left) &&
      ts.isPropertyAccessExpression(node.left.expression) &&
      ts.isIdentifier(node.left.expression.expression) &&
      node.left.expression.expression.text === 'process' &&
      node.left.expression.name.text === 'env' &&
      node.left.name.text === 'NODE_TLS_REJECT_UNAUTHORIZED' &&
      constantString(node.right) === '0'
    ) {
      report('TG007', node, undefined, 0.99);
    }

    if (ts.isCallExpression(node)) {
      const name = ts.isIdentifier(node.expression)
        ? node.expression.text
        : ts.isPropertyAccessExpression(node.expression)
          ? node.expression.name.text
          : '';

      if (name === 'cors') {
        for (const argument of node.arguments) {
          if (
            ts.isObjectLiteralExpression(argument) &&
            propertyIsString(argument, 'origin', '*') &&
            argument.properties.some(
              (property) =>
                ts.isPropertyAssignment(property) &&
                propertyName(property.name) === 'credentials' &&
                property.initializer.kind === ts.SyntaxKind.TrueKeyword,
            )
          ) {
            report('TG009', argument, undefined, 0.94);
          }
        }
      }
    }

    ts.forEachChild(node, visit);
  };

  visit(sourceFile);
  findings.sort(
    (a, b) =>
      a.line - b.line ||
      a.column - b.column ||
      a.ruleId.localeCompare(b.ruleId),
  );

  const parseDiagnostics = (
    sourceFile as ts.SourceFile & {
      parseDiagnostics?: readonly ts.Diagnostic[];
    }
  ).parseDiagnostics;
  const parseErrors = (parseDiagnostics ?? []).map((diagnostic) => {
    const message = ts.flattenDiagnosticMessageText(
      diagnostic.messageText,
      ' ',
    );
    if (diagnostic.start === undefined) return message;
    const position = sourceFile.getLineAndCharacterOfPosition(diagnostic.start);
    return `Line ${position.line + 1}, column ${position.character + 1}: ${message}`;
  });

  return makeReport(findings, source, RULES.length, parseErrors);
}

export function analyzeProject(files: SourceFileInput[]): ProjectAuditReport {
  const findings: Finding[] = [];
  const parseErrors: string[] = [];
  let linesAnalyzed = 0;
  let filesAnalyzed = 0;
  let rulesRun = 0;

  for (const file of files) {
    const report = analyzeSource(file.source, file.fileName);
    findings.push(...report.findings);
    linesAnalyzed += report.linesAnalyzed;
    rulesRun = report.rulesRun;
    parseErrors.push(
      ...report.parseErrors.map((error) => `${file.fileName}: ${error}`),
    );
    if (report.parseErrors.length === 0) filesAnalyzed += 1;
  }

  const combined = makeReport(
    findings,
    '\n'.repeat(Math.max(0, linesAnalyzed - 1)),
    rulesRun,
    parseErrors,
  );
  return { ...combined, linesAnalyzed, filesAnalyzed };
}
