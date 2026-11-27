/**
 * Lightweight, file-local interprocedural taint tracking.
 *
 * The tracker intentionally uses AST/scope information that is already
 * available to an ESLint rule. It builds small summaries for functions:
 * which parameters reach return values and which parameters reach sinks.
 * Call sites then map those parameter origins back to concrete arguments.
 */

'use strict';

const { findVariable } = require('./find-variable');
const { getImportAccessPath } = require('./import-utils');

const WILDCARD_PACKAGE_NAMES = {
  includes() {
    return true;
  },
};

const DEFAULT_SOURCES = Object.freeze([
  'req.query',
  'req.body',
  'req.params',
  'req.cookies',
  'req.headers',
  'request.query',
  'request.body',
  'request.params',
  'request.cookies',
  'request.headers',
  'ctx.query',
  'ctx.request.query',
  'ctx.request.body',
  'ctx.params',
  'ctx.cookies',
  'event.queryStringParameters',
  'event.pathParameters',
  'event.body',
  'process.argv',
  'process.env',
]);

const DEFAULT_SINKS = Object.freeze([
  { name: 'eval', args: [0], category: 'code-execution' },
  { name: 'Function', args: 'all', category: 'code-execution' },
  { name: 'vm.runInContext', args: [0], category: 'code-execution' },
  { name: 'vm.runInNewContext', args: [0], category: 'code-execution' },
  { name: 'vm.runInThisContext', args: [0], category: 'code-execution' },
  { name: 'child_process.exec', args: [0], category: 'command-injection' },
  { name: 'child_process.execSync', args: [0], category: 'command-injection' },
  { name: 'child_process.execFile', args: [0, 1], category: 'command-injection' },
  { name: 'child_process.execFileSync', args: [0, 1], category: 'command-injection' },
  { name: 'child_process.spawn', args: [0, 1], category: 'command-injection' },
  { name: 'child_process.spawnSync', args: [0, 1], category: 'command-injection' },
  { name: 'require', args: [0], category: 'code-loading' },
  { name: '*.query', args: [0], category: 'sql-injection' },
  { name: '*.execute', args: [0], category: 'sql-injection' },
  { name: '*.raw', args: [0], category: 'sql-injection' },
  { name: 'knex.raw', args: [0], category: 'sql-injection' },
  { name: 'sequelize.query', args: [0], category: 'sql-injection' },
  { name: 'fs.readFile', args: [0], category: 'path-injection' },
  { name: 'fs.readFileSync', args: [0], category: 'path-injection' },
  { name: 'fs.writeFile', args: [0], category: 'path-injection' },
  { name: 'fs.writeFileSync', args: [0], category: 'path-injection' },
  { name: 'fs.createReadStream', args: [0], category: 'path-injection' },
  { name: 'fs.createWriteStream', args: [0], category: 'path-injection' },
]);

const DEFAULT_SANITIZERS = Object.freeze([
  'sanitize',
  'sanitize*',
  'sanitizeInput',
  'sanitise',
  'sanitise*',
  'sanitiseInput',
  'escape',
  'escape*',
  'escapeHtml',
  'escapeHTML',
  'escapeSql',
  'escapeSQL',
  'encodeURIComponent',
  'encodeURI',
  'parseInt',
  'parseFloat',
  'Number',
  'Boolean',
  'validator.escape',
  'validator.trim',
  'DOMPurify.sanitize',
  'dompurify.sanitize',
  'xss',
  'xssClean',
  'mysql.escape',
  'connection.escape',
  'pool.escape',
  'sqlstring.escape',
  'SqlString.escape',
]);

function makeOrigin(base, path = []) {
  return JSON.stringify({ base: String(base), path });
}

function parseOrigin(origin) {
  try {
    const parsed = JSON.parse(origin);
    if (parsed && typeof parsed.base === 'string' && Array.isArray(parsed.path)) {
      return parsed;
    }
  } catch {
    // Fall through to a safe empty origin.
  }
  return { base: String(origin), path: [] };
}

class Taint {
  constructor(sources = [], origins = [], props = new Map()) {
    this.sources = new Set(sources);
    this.origins = new Set(origins);
    this.props = new Map(props);
  }

  static none() {
    return new Taint();
  }

  static source(label) {
    return new Taint([label || 'untrusted input']);
  }

  static parameter(index) {
    return new Taint([], [makeOrigin(index, [])]);
  }

  static receiver() {
    return new Taint([], [makeOrigin('this', [])]);
  }

  clone() {
    const props = new Map();
    for (const [key, value] of this.props) {
      props.set(key, value instanceof Taint ? value.clone() : Taint.none());
    }
    return new Taint(this.sources, this.origins, props);
  }

  union(other) {
    const result = this.clone();
    result.mergeInPlace(other);
    return result;
  }

  mergeInPlace(other) {
    if (!other) {
      return this;
    }

    other.sources.forEach((source) => this.sources.add(source));
    other.origins.forEach((origin) => this.origins.add(origin));

    for (const [key, value] of other.props) {
      const existing = this.props.get(key);
      if (existing) {
        existing.mergeInPlace(value);
      } else {
        this.props.set(key, value.clone());
      }
    }

    return this;
  }

  property(key) {
    const propertyName = key == null ? '*' : String(key);
    let result = Taint.none();

    this.sources.forEach((source) => result.sources.add(source));

    const explicit = this.props.get(propertyName) || (propertyName === '*' ? undefined : this.props.get('*'));
    if (explicit) {
      return result.union(explicit);
    }

    if (propertyName === '*') {
      for (const value of this.props.values()) {
        result = result.union(value);
      }
    }

    for (const origin of this.origins) {
      const parsed = parseOrigin(origin);
      result.origins.add(makeOrigin(parsed.base, [...parsed.path, propertyName]));
    }

    return result;
  }

  withProperty(key, value) {
    const result = this.clone();
    result.props.set(String(key), value ? value.clone() : Taint.none());
    return result;
  }

  hasDirectTaint() {
    return this.sources.size > 0 || this.origins.size > 0;
  }

  hasAnyOrigin() {
    if (this.origins.size > 0) {
      return true;
    }
    for (const value of this.props.values()) {
      if (value.hasAnyOrigin()) {
        return true;
      }
    }
    return false;
  }

  hasAnyTaint() {
    if (this.hasDirectTaint()) {
      return true;
    }
    for (const value of this.props.values()) {
      if (value.hasAnyTaint()) {
        return true;
      }
    }
    return false;
  }

  collectSources(into = new Set()) {
    this.sources.forEach((source) => into.add(source));
    for (const value of this.props.values()) {
      value.collectSources(into);
    }
    return into;
  }

  concreteOnly() {
    const result = Taint.none();
    this.sources.forEach((source) => result.sources.add(source));
    for (const [key, value] of this.props) {
      const concrete = value.concreteOnly();
      if (concrete.hasAnyTaint()) {
        result.props.set(key, concrete);
      }
    }
    return result;
  }
}

class Env {
  constructor(parent = null) {
    this.parent = parent;
    this.vars = new Map();
    this.capture = null;
  }

  declare(name, taint) {
    if (!name) {
      return;
    }
    this.vars.set(name, taint ? taint.clone() : Taint.none());
  }

  get(name) {
    if (this.capture && this.capture.has(name)) {
      return this.capture.get(name).clone();
    }
    if (this.vars.has(name)) {
      return this.vars.get(name).clone();
    }
    return this.parent ? this.parent.get(name) : Taint.none();
  }

  assign(name, taint) {
    if (!name) {
      return;
    }
    if (this.capture) {
      this.capture.set(name, taint ? taint.clone() : Taint.none());
      return;
    }

    if (this.vars.has(name)) {
      this.vars.set(name, taint ? taint.clone() : Taint.none());
      return;
    }

    if (this.parent) {
      this.parent.assign(name, taint);
      return;
    }

    this.vars.set(name, taint ? taint.clone() : Taint.none());
  }

  fork() {
    const forked = new Env(this);
    forked.capture = new Map();
    return forked;
  }

  mergeFork(forked) {
    if (!forked || !forked.capture) {
      return;
    }
    for (const [name, taint] of forked.capture) {
      const merged = this.get(name).union(taint);
      this.assign(name, merged);
    }
  }
}

function toArray(value) {
  if (value == null) {
    return [];
  }
  return Array.isArray(value) ? value : [value];
}

function normalizeArgumentIndexes(value) {
  if (value === 'all' || value === '*' || value === true) {
    return 'all';
  }
  if (typeof value === 'number') {
    return [value];
  }
  if (Array.isArray(value)) {
    return value.filter((index) => typeof index === 'number');
  }
  if (typeof value === 'string') {
    const parsed = Number(value);
    return Number.isInteger(parsed) ? [parsed] : [0];
  }
  return [0];
}

function normalizeMatcher(entry, kind) {
  if (entry == null) {
    return null;
  }

  if (entry instanceof RegExp) {
    return { regex: entry, args: kind === 'sink' ? [0] : undefined };
  }

  if (typeof entry === 'string') {
    let name = entry;
    let args;
    let regex = null;
    const argumentMatch = name.match(/[#@[](\d+)\]?$/);
    if (argumentMatch) {
      const index = Number(argumentMatch[1]);
      name = name.slice(0, argumentMatch.index);
      args = [index];
    }
    const regexMatch = name.match(/^\/(.+)\/([gimsuy]*)$/);
    if (regexMatch) {
      regex = new RegExp(regexMatch[1], regexMatch[2]);
      name = null;
    }
    return { name, regex, args: kind === 'sink' ? normalizeArgumentIndexes(args) : undefined };
  }

  if (typeof entry !== 'object') {
    return null;
  }

  let name = entry.name || entry.names || entry.pattern || entry.patterns || entry.callee || entry.function || entry.functions || entry.identifier || null;
  if (name && !Array.isArray(name) && typeof name === 'object') {
    name = name.name || name.path || null;
  }
  if (!name && (entry.object || entry.receiver) && (entry.method || entry.property)) {
    name = `${entry.object || entry.receiver}.${entry.method || entry.property}`;
  }
  if (!name && entry.method) {
    name = entry.method;
  }

  const matcher = {
    name,
    regex: entry.regex instanceof RegExp ? entry.regex : null,
    label: entry.label || entry.message || null,
    category: entry.category || entry.kind || null,
    construct: Boolean(entry.construct || entry.new),
  };

  if (kind === 'sink') {
    matcher.args = normalizeArgumentIndexes(
      entry.args ??
        entry.arguments ??
        entry.parameters ??
        entry.params ??
        entry.positions ??
        entry.argumentIndices ??
        entry.parameterIndices ??
        entry.indices ??
        entry.index ??
        entry.argument ?? [0]
    );
  }

  if (!matcher.name && !matcher.regex) {
    return null;
  }

  return matcher;
}

function normalizeMatcherList(value, kind) {
  let entries = value;

  if (entries && typeof entries === 'object' && !(entries instanceof RegExp) && !Array.isArray(entries)) {
    const looksLikeMatcher = Boolean(
      entries.name ||
        entries.names ||
        entries.pattern ||
        entries.patterns ||
        entries.regex ||
        entries.callee ||
        entries.function ||
        entries.method ||
        entries.object ||
        entries.receiver
    );
    if (!looksLikeMatcher) {
      entries = Object.entries(entries).map(([name, config]) => {
        if (Array.isArray(config) && kind === 'sink') {
          return { name, args: config };
        }
        if (config && typeof config === 'object') {
          return { name, ...config };
        }
        return { name };
      });
    }
  }

  return toArray(entries)
    .map((entry) => normalizeMatcher(entry, kind))
    .filter(Boolean);
}

function normalizeTaintOptions(rawOptions = {}, overrides = {}) {
  const optionsArray = Array.isArray(rawOptions) ? rawOptions : [];
  let optionBag = rawOptions && typeof rawOptions === 'object' && !Array.isArray(rawOptions) ? rawOptions : {};

  if (optionsArray.length) {
    if (optionsArray[0] && typeof optionsArray[0] === 'object' && !Array.isArray(optionsArray[0])) {
      optionBag = optionsArray[0];
    } else if (Array.isArray(optionsArray[0])) {
      optionBag = {
        sources: optionsArray[0],
        sinks: optionsArray[1],
        sanitizers: optionsArray[2],
      };
    }
  }

  const merged = { ...overrides, ...optionBag };
  const useDefaults = merged.useDefaults !== false && merged.extendsDefaults !== false && merged.defaults !== false;

  const customSources = merged.sources ?? merged.source ?? merged.sourcePatterns ?? merged.taintSources;
  const customSinks = merged.sinks ?? merged.sink ?? merged.sinkPatterns ?? merged.taintSinks;
  const customSanitizers = merged.sanitizers ?? merged.sanitizer ?? merged.sanitizerFunctions ?? merged.sanitize;

  return {
    sources: [...normalizeMatcherList(useDefaults ? DEFAULT_SOURCES : [], 'source'), ...normalizeMatcherList(customSources, 'source')],
    sinks: [...normalizeMatcherList(useDefaults ? DEFAULT_SINKS : [], 'sink'), ...normalizeMatcherList(customSinks, 'sink')],
    sanitizers: [...normalizeMatcherList(useDefaults ? DEFAULT_SANITIZERS : [], 'sanitizer'), ...normalizeMatcherList(customSanitizers, 'sanitizer')],
    propagateThroughUnknownCalls: merged.propagateThroughUnknownCalls !== false,
    followCrossFunction: merged.followCrossFunction !== false,
    reportLocation: merged.reportLocation === 'call' ? 'call' : 'sink',
    maxDepth: typeof merged.maxDepth === 'number' ? merged.maxDepth : 8,
  };
}

function escapeRegExp(value) {
  return value.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^.]*');
}

function pathMatchesPattern(pattern, path, { prefix = false } = {}) {
  if (!pattern || !path) {
    return false;
  }

  if (pattern === path) {
    return true;
  }

  if (pattern.includes('*')) {
    const suffix = prefix ? '(\\..+)?' : '';
    const regex = new RegExp(`^${escapeRegExp(pattern)}${suffix}$`);
    if (regex.test(path)) {
      return true;
    }
  }

  if (prefix && path.startsWith(`${pattern}.`)) {
    return true;
  }

  if (!pattern.includes('.') && path.split('.').pop() === pattern) {
    return true;
  }

  return false;
}

function matcherMatchesPath(matcher, names, { prefix = false } = {}) {
  const nameList = Array.isArray(names) ? names : [names];

  for (const name of nameList) {
    if (!name) {
      continue;
    }
    if (matcher.regex && matcher.regex.test(name)) {
      return true;
    }
    if (matcher.name) {
      for (const candidate of toArray(matcher.name)) {
        if (pathMatchesPattern(candidate, name, { prefix })) {
          return true;
        }
      }
    }
  }

  return false;
}

function getAstPath(node) {
  if (!node || typeof node.type !== 'string') {
    return '';
  }

  if (node.type === 'Identifier') {
    return node.name;
  }

  if (node.type === 'Literal') {
    return String(node.value);
  }

  if (node.type === 'ThisExpression') {
    return 'this';
  }

  if (node.type === 'CallExpression' || node.type === 'NewExpression') {
    const calleePath = getAstPath(node.callee);
    if (node.callee.type === 'Identifier' && node.callee.name === 'require' && node.arguments[0]?.type === 'Literal') {
      return String(node.arguments[0].value);
    }
    return node.type === 'NewExpression' ? `new ${calleePath}` : calleePath;
  }

  if (node.type === 'MemberExpression') {
    const objectPath = getAstPath(node.object) || '*';
    if (!node.computed && node.property.type === 'Identifier') {
      return `${objectPath}.${node.property.name}`;
    }
    if (node.computed && node.property.type === 'Literal') {
      return `${objectPath}.${String(node.property.value)}`;
    }
    return `${objectPath}.*`;
  }

  return '';
}

function isFunctionNode(node) {
  return node && (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression');
}

class TaintTracker {
  constructor(context, rawOptions = {}, overrides = {}) {
    this.context = context;
    this.sourceCode = context.sourceCode || (typeof context.getSourceCode === 'function' ? context.getSourceCode() : null);
    this.options = normalizeTaintOptions(rawOptions, overrides);
    this.summaries = new WeakMap();
    this.functionNames = new Map();
    this.functionNodes = new Set();
    this.stack = [];
    this.findings = [];
    this.reportedNodes = new WeakSet();
  }

  getScope(node) {
    try {
      if (this.sourceCode && typeof this.sourceCode.getScope === 'function') {
        return this.sourceCode.getScope(node);
      }
      if (this.context && typeof this.context.getScope === 'function') {
        return this.context.getScope();
      }
    } catch {
      // Scope analysis is optional for syntactic fallback.
    }
    return null;
  }

  analyze(program) {
    if (!program) {
      return this.findings;
    }

    this.collectFunctions(program, null);
    const env = new Env();
    this.walk(program, env);
    return this.findings;
  }

  collectFunctions(node, parent) {
    if (!node || (typeof node.type !== 'object' && typeof node.type !== 'string')) {
      return;
    }

    if (isFunctionNode(node)) {
      this.functionNodes.add(node);
      const name = this.getFunctionName(node, parent);
      if (name) {
        if (!this.functionNames.has(name)) {
          this.functionNames.set(name, new Set());
        }
        this.functionNames.get(name).add(node);
      }
    }

    for (const key of Object.keys(node)) {
      if (key === 'parent') {
        continue;
      }
      const value = node[key];
      if (Array.isArray(value)) {
        for (const child of value) {
          if (child && typeof child.type === 'string') {
            this.collectFunctions(child, node);
          }
        }
      } else if (value && typeof value.type === 'string') {
        this.collectFunctions(value, node);
      }
    }
  }

  getFunctionName(node, parent) {
    if (node.id && node.id.type === 'Identifier') {
      return node.id.name;
    }
    if (parent && parent.type === 'VariableDeclarator' && parent.id.type === 'Identifier' && parent.init === node) {
      return parent.id.name;
    }
    if (parent && parent.type === 'AssignmentExpression' && parent.right === node && parent.left.type === 'Identifier') {
      return parent.left.name;
    }
    return null;
  }

  getDescriptorNames(node, scope, { resolveImports = true } = {}) {
    const names = [];
    const astPath = getAstPath(node);
    if (astPath) {
      names.push(astPath);
    }

    if (resolveImports && (node.type === 'Identifier' || node.type === 'MemberExpression')) {
      try {
        const info = getImportAccessPath({ node, scope, packageNames: WILDCARD_PACKAGE_NAMES });
        if (info && info.packageName) {
          names.push([info.packageName, ...(info.path || [])].join('.'));
        }
      } catch {
        // Syntactic matching still works without import resolution.
      }
    }

    for (const name of [...names]) {
      if (name.startsWith('node:')) {
        names.push(name.slice('node:'.length));
      }
    }

    return [...new Set(names)];
  }

  matchSource(node) {
    if (!node || (node.type !== 'Identifier' && node.type !== 'MemberExpression' && node.type !== 'CallExpression' && node.type !== 'NewExpression')) {
      return null;
    }
    const names = this.getDescriptorNames(node, null, { resolveImports: false });
    return this.options.sources.find((matcher) => matcherMatchesPath(matcher, names, { prefix: true })) || null;
  }

  matchSink(callNode) {
    const scope = this.getScope(callNode);
    const names = this.getDescriptorNames(callNode.callee, scope);
    if (callNode.type === 'NewExpression') {
      names.push(`new ${getAstPath(callNode.callee)}`);
    }
    return (
      this.options.sinks.find((matcher) => {
        if (matcher.construct && callNode.type !== 'NewExpression') {
          return false;
        }
        return matcherMatchesPath(matcher, names, { prefix: false });
      }) || null
    );
  }

  matchSanitizer(callNode) {
    const scope = this.getScope(callNode);
    const names = this.getDescriptorNames(callNode.callee, scope);
    return this.options.sanitizers.find((matcher) => matcherMatchesPath(matcher, names, { prefix: false })) || null;
  }

  sourceLabel(matcher, node) {
    return matcher.label || matcher.name || getAstPath(node) || 'untrusted input';
  }

  addFinding(sinkNode, matcher, sources, reportNode = sinkNode) {
    const node = this.options.reportLocation === 'call' && reportNode ? reportNode : sinkNode;
    if (!node || this.reportedNodes.has(node)) {
      return;
    }
    this.reportedNodes.add(node);
    const sourceNames = [...(sources || [])].filter(Boolean).slice(0, 4);
    const sinkName = matcher.label || matcher.name || getAstPath(sinkNode.callee) || 'security-sensitive call';
    const sourceText = sourceNames.length ? sourceNames.join(', ') : 'untrusted input';
    const category = matcher.category ? `${matcher.category} ` : '';
    this.findings.push({
      node,
      message: `Tainted data from ${sourceText} reaches ${category}sink ${sinkName}; sanitize or validate it before this call.`,
    });
  }

  currentSummary() {
    return this.stack[this.stack.length - 1] || null;
  }

  analyzeFunction(fnNode, closureEnv = null) {
    if (!this.options.followCrossFunction || !isFunctionNode(fnNode)) {
      return { node: fnNode, returns: Taint.none(), hazards: [] };
    }

    const existing = this.summaries.get(fnNode);
    if (existing) {
      return existing;
    }

    const summary = { node: fnNode, returns: Taint.none(), hazards: [] };
    this.summaries.set(fnNode, summary);
    this.stack.push(summary);

    try {
      const env = new Env(closureEnv ? this.createConcreteClosureParent(closureEnv) : null);
      fnNode.params.forEach((param, index) => this.bindPattern(param, Taint.parameter(index), env, true));

      if (fnNode.body && fnNode.body.type === 'BlockStatement') {
        this.walk(fnNode.body, env);
      } else if (fnNode.body) {
        const bodyTaint = this.evaluate(fnNode.body, env);
        summary.returns = summary.returns.union(bodyTaint);
      }
    } finally {
      this.stack.pop();
    }

    return summary;
  }

  createConcreteClosureParent(closureEnv) {
    const parent = new Env();
    if (!closureEnv) {
      return parent;
    }

    let current = closureEnv;
    while (current) {
      for (const [name, taint] of current.vars || []) {
        const concrete = taint.concreteOnly();
        if (concrete.hasAnyTaint() && !parent.vars.has(name)) {
          parent.declare(name, concrete);
        }
      }
      current = current.parent;
    }
    return parent;
  }

  walk(node, env) {
    if (!node || typeof node.type !== 'string') {
      return;
    }

    switch (node.type) {
      case 'Program':
      case 'BlockStatement': {
        const blockEnv = node.type === 'BlockStatement' ? new Env(env) : env;
        for (const statement of node.body) {
          this.walk(statement, blockEnv);
        }
        return;
      }

      case 'ExpressionStatement':
        this.evaluate(node.expression, env);
        return;

      case 'VariableDeclaration':
        for (const declarator of node.declarations) {
          const taint = declarator.init ? this.evaluate(declarator.init, env) : Taint.none();
          this.bindPattern(declarator.id, taint, env, true);
        }
        return;

      case 'FunctionDeclaration':
        if (node.id) {
          env.declare(node.id.name, Taint.none());
        }
        this.analyzeFunction(node, env);
        return;

      case 'FunctionExpression':
      case 'ArrowFunctionExpression':
        this.analyzeFunction(node, env);
        return;

      case 'ReturnStatement': {
        const taint = node.argument ? this.evaluate(node.argument, env) : Taint.none();
        const summary = this.currentSummary();
        if (summary) {
          summary.returns = summary.returns.union(taint);
        }
        return;
      }

      case 'IfStatement': {
        this.evaluate(node.test, env);
        const consequentEnv = env.fork();
        this.walk(node.consequent, consequentEnv);
        env.mergeFork(consequentEnv);
        if (node.alternate) {
          const alternateEnv = env.fork();
          this.walk(node.alternate, alternateEnv);
          env.mergeFork(alternateEnv);
        }
        return;
      }

      case 'SwitchStatement': {
        this.evaluate(node.discriminant, env);
        const switchEnv = env.fork();
        for (const switchCase of node.cases) {
          if (switchCase.test) {
            this.evaluate(switchCase.test, switchEnv);
          }
          for (const statement of switchCase.consequent) {
            this.walk(statement, switchEnv);
          }
        }
        env.mergeFork(switchEnv);
        return;
      }

      case 'TryStatement': {
        const tryEnv = env.fork();
        this.walk(node.block, tryEnv);
        env.mergeFork(tryEnv);
        if (node.handler) {
          const handlerEnv = env.fork();
          if (node.handler.param) {
            this.bindPattern(node.handler.param, Taint.none(), handlerEnv, true);
          }
          this.walk(node.handler.body, handlerEnv);
          env.mergeFork(handlerEnv);
        }
        if (node.finalizer) {
          this.walk(node.finalizer, new Env(env));
        }
        return;
      }

      case 'WhileStatement':
      case 'DoWhileStatement':
      case 'ForStatement': {
        const loopEnv = env.fork();
        if (node.type === 'ForStatement') {
          if (node.init?.type === 'VariableDeclaration') {
            this.walk(node.init, loopEnv);
          } else if (node.init) {
            this.evaluate(node.init, loopEnv);
          }
          if (node.test) {
            this.evaluate(node.test, loopEnv);
          }
          if (node.update) {
            this.evaluate(node.update, loopEnv);
          }
        } else {
          this.evaluate(node.test, loopEnv);
        }
        this.walk(node.body, loopEnv);
        env.mergeFork(loopEnv);
        return;
      }

      case 'ForInStatement':
      case 'ForOfStatement': {
        const loopEnv = env.fork();
        const iterableTaint = this.evaluate(node.right, loopEnv);
        if (node.left.type === 'VariableDeclaration') {
          for (const declarator of node.left.declarations) {
            this.bindPattern(declarator.id, iterableTaint.property(node.type === 'ForOfStatement' ? '*' : '*'), loopEnv, true);
          }
        } else {
          this.bindPattern(node.left, iterableTaint.property('*'), loopEnv, false);
        }
        this.walk(node.body, loopEnv);
        env.mergeFork(loopEnv);
        return;
      }

      case 'ThrowStatement':
        if (node.argument) {
          this.evaluate(node.argument, env);
        }
        return;

      case 'LabeledStatement':
        this.walk(node.body, env);
        return;

      default:
        this.walkChildren(node, env);
    }
  }

  walkChildren(node, env) {
    for (const key of Object.keys(node)) {
      if (key === 'parent' || key === 'loc' || key === 'range' || key === 'start' || key === 'end' || key === 'tokens' || key === 'comments') {
        continue;
      }
      const value = node[key];
      if (Array.isArray(value)) {
        for (const child of value) {
          if (child && typeof child.type === 'string') {
            this.walk(child, env);
          }
        }
      } else if (value && typeof value.type === 'string') {
        this.walk(value, env);
      }
    }
  }

  evaluateChildren(node, env) {
    for (const key of Object.keys(node)) {
      if (key === 'parent' || key === 'loc' || key === 'range' || key === 'start' || key === 'end') {
        continue;
      }
      const value = node[key];
      if (Array.isArray(value)) {
        for (const child of value) {
          if (child && typeof child.type === 'string') {
            this.evaluate(child, env);
          }
        }
      } else if (value && typeof value.type === 'string') {
        this.evaluate(value, env);
      }
    }
  }

  bindPattern(pattern, taint, env, declare) {
    if (!pattern) {
      return;
    }
    const value = taint || Taint.none();

    switch (pattern.type) {
      case 'Identifier':
        if (declare) {
          env.declare(pattern.name, value);
        } else {
          env.assign(pattern.name, value);
        }
        return;

      case 'ObjectPattern':
        for (const property of pattern.properties) {
          if (property.type === 'RestElement') {
            this.bindPattern(property.argument, value, env, declare);
            continue;
          }
          const key = this.getPatternKey(property);
          const childTaint = value.property(key);
          this.bindPattern(property.value, childTaint, env, declare);
        }
        return;

      case 'ArrayPattern':
        pattern.elements.forEach((element, index) => {
          if (!element) {
            return;
          }
          if (element.type === 'RestElement') {
            this.bindPattern(element.argument, value.property('*'), env, declare);
          } else {
            this.bindPattern(element, value.property(String(index)), env, declare);
          }
        });
        return;

      case 'AssignmentPattern': {
        const defaultTaint = pattern.right ? this.evaluate(pattern.right, env) : Taint.none();
        this.bindPattern(pattern.left, value.union(defaultTaint), env, declare);
        return;
      }

      case 'RestElement':
        this.bindPattern(pattern.argument, value, env, declare);
        return;

      case 'MemberExpression':
        this.assignToMember(pattern, value, env);
        return;

      default:
        // Unsupported patterns are intentionally ignored.
        break;
    }
  }

  getPatternKey(property) {
    if (!property) {
      return '*';
    }
    if (!property.computed && property.key && property.key.type === 'Identifier') {
      return property.key.name;
    }
    if (property.key && property.key.type === 'Literal') {
      return String(property.key.value);
    }
    return '*';
  }

  assignToMember(memberNode, value, env) {
    const segments = [];
    let current = memberNode;
    while (current && current.type === 'MemberExpression') {
      if (!current.computed && current.property.type === 'Identifier') {
        segments.unshift(current.property.name);
      } else if (current.computed && current.property.type === 'Literal') {
        segments.unshift(String(current.property.value));
      } else {
        segments.unshift('*');
      }
      current = current.object;
    }

    if (!current || current.type !== 'Identifier') {
      return;
    }

    const root = this.setNestedProperty(env.get(current.name), segments, 0, value);
    env.assign(current.name, root);
  }

  setNestedProperty(root, segments, index, value) {
    const key = segments[index];
    if (index === segments.length - 1) {
      return root.withProperty(key, value);
    }
    const existing = root.props.get(key) || Taint.none();
    return root.withProperty(key, this.setNestedProperty(existing, segments, index + 1, value));
  }

  evaluate(node, env) {
    if (!node || typeof node.type !== 'string') {
      return Taint.none();
    }

    const sourceMatcher = this.matchSource(node);
    if (sourceMatcher && node.type !== 'CallExpression' && node.type !== 'NewExpression') {
      this.evaluateChildren(node, env);
      return Taint.source(this.sourceLabel(sourceMatcher, node));
    }

    switch (node.type) {
      case 'Identifier':
        return env.get(node.name);

      case 'Literal':
        return Taint.none();

      case 'ThisExpression':
        return Taint.receiver();

      case 'TemplateLiteral': {
        let result = Taint.none();
        for (const expression of node.expressions) {
          result = result.union(this.evaluate(expression, env));
        }
        return result;
      }

      case 'BinaryExpression':
      case 'LogicalExpression': {
        const left = this.evaluate(node.left, env);
        const right = this.evaluate(node.right, env);
        return left.union(right);
      }

      case 'ConditionalExpression': {
        this.evaluate(node.test, env);
        const consequent = this.evaluate(node.consequent, env);
        const alternate = this.evaluate(node.alternate, env);
        return consequent.union(alternate);
      }

      case 'AssignmentExpression': {
        const right = this.evaluate(node.right, env);
        let value = right;
        if (node.operator !== '=') {
          const oldValue = this.evaluate(node.left, env);
          value = oldValue.union(right);
        }
        this.bindPattern(node.left, value, env, false);
        return value;
      }

      case 'UpdateExpression': {
        const oldValue = this.evaluate(node.argument, env);
        this.bindPattern(node.argument, oldValue, env, false);
        return oldValue;
      }

      case 'MemberExpression': {
        const objectTaint = this.evaluate(node.object, env);
        let keyTaint = Taint.none();
        let key = '*';
        if (!node.computed && node.property.type === 'Identifier') {
          key = node.property.name;
        } else if (node.computed && node.property.type === 'Literal') {
          key = String(node.property.value);
          keyTaint = Taint.none();
        } else if (node.computed) {
          keyTaint = this.evaluate(node.property, env);
        }
        return objectTaint.property(key).union(keyTaint);
      }

      case 'ArrayExpression': {
        const result = Taint.none();
        node.elements.forEach((element, index) => {
          if (!element) {
            return;
          }
          if (element.type === 'SpreadElement') {
            result.mergeInPlace(this.evaluate(element.argument, env));
          } else {
            const elementTaint = this.evaluate(element, env);
            if (elementTaint.hasAnyTaint()) {
              result.props.set(String(index), elementTaint);
            }
          }
        });
        return result;
      }

      case 'ObjectExpression': {
        const result = Taint.none();
        for (const property of node.properties) {
          if (property.type === 'SpreadElement') {
            result.mergeInPlace(this.evaluate(property.argument, env));
            continue;
          }
          const key = this.getPatternKey(property);
          const valueNode = property.value || property.argument;
          const value = this.evaluate(valueNode, env);
          if (value.hasAnyTaint()) {
            result.props.set(key, value);
          }
        }
        return result;
      }

      case 'CallExpression':
      case 'NewExpression':
        return this.evaluateCallLike(node, env);

      case 'ArrowFunctionExpression':
      case 'FunctionExpression':
        this.analyzeFunction(node, env);
        return Taint.none();

      case 'AwaitExpression':
      case 'YieldExpression':
        return node.argument ? this.evaluate(node.argument, env) : Taint.none();

      case 'SpreadElement':
        return this.evaluate(node.argument, env);

      case 'ParenthesizedExpression':
        return this.evaluate(node.expression, env);

      default: {
        let result = Taint.none();
        for (const child of this.getChildExpressionNodes(node)) {
          result = result.union(this.evaluate(child, env));
        }
        return result;
      }
    }
  }

  getChildExpressionNodes(node) {
    const children = [];
    for (const key of Object.keys(node)) {
      if (key === 'parent' || key === 'loc' || key === 'range' || key === 'start' || key === 'end') {
        continue;
      }
      const value = node[key];
      if (Array.isArray(value)) {
        for (const child of value) {
          if (child && typeof child.type === 'string') {
            children.push(child);
          }
        }
      } else if (value && typeof value.type === 'string') {
        children.push(value);
      }
    }
    return children;
  }

  evaluateCallLike(node, env) {
    const receiverTaint = node.callee.type === 'MemberExpression' ? this.evaluate(node.callee.object, env) : Taint.none();
    if (node.callee.type === 'MemberExpression' && node.callee.computed) {
      this.evaluate(node.callee.property, env);
    }

    const argTaints = node.arguments.map((argument) => this.evaluate(argument, env));

    const sourceMatcher = this.matchSource(node);
    if (sourceMatcher) {
      return Taint.source(this.sourceLabel(sourceMatcher, node));
    }

    const sinkMatcher = this.matchSink(node);
    if (sinkMatcher) {
      this.checkSinkArguments(node, sinkMatcher, argTaints);
    }

    const sanitizerMatcher = this.matchSanitizer(node);
    if (sanitizerMatcher) {
      return Taint.none();
    }

    this.analyzeCallbackArguments(node, argTaints, receiverTaint);

    let result = Taint.none();
    const callees = this.options.followCrossFunction ? this.resolveCalleeFunctions(node, env) : [];

    for (const callee of callees) {
      const summary = this.analyzeFunction(callee, env);
      const mappedReturn = this.mapTaint(summary.returns, argTaints, receiverTaint);
      result = result.union(mappedReturn);

      for (const hazard of [...summary.hazards]) {
        const mappedHazard = this.mapTaint(hazard.taint, argTaints, receiverTaint);
        if (mappedHazard.hasAnyTaint()) {
          this.registerMappedHazard(hazard, mappedHazard, node);
        }
      }
    }

    if (this.options.propagateThroughUnknownCalls && callees.length === 0) {
      result = result.union(receiverTaint);
      for (const argTaint of argTaints) {
        result = result.union(argTaint);
      }
    }

    return result;
  }

  checkSinkArguments(callNode, matcher, argTaints) {
    const indexes = matcher.args || [0];
    const selected = indexes === 'all' ? argTaints.map((_, index) => index) : indexes;

    for (const index of selected) {
      const taint = argTaints[index];
      if (!taint || !taint.hasAnyTaint()) {
        continue;
      }

      const sources = taint.collectSources();
      if (sources.size > 0) {
        this.addFinding(callNode, matcher, sources);
      }

      const summary = this.currentSummary();
      if (summary && taint.hasAnyOrigin()) {
        summary.hazards.push({
          sinkNode: callNode,
          matcher,
          taint: taint.clone(),
        });
      }
    }
  }

  analyzeCallbackArguments(callNode, argTaints, receiverTaint) {
    if (!this.options.followCrossFunction) {
      return;
    }

    const methodName = this.getCallMethodName(callNode);
    const iterativeMethods = new Set(['map', 'forEach', 'flatMap', 'filter', 'find', 'findIndex', 'some', 'every', 'reduce', 'reduceRight']);

    callNode.arguments.forEach((argument, argumentIndex) => {
      const callbackNode = this.unwrapFunctionNode(argument);
      if (!callbackNode) {
        return;
      }

      const summary = this.summaries.get(callbackNode) || this.analyzeFunction(callbackNode);
      let callbackArguments = [];

      if (methodName === 'then' && argumentIndex === 0) {
        callbackArguments = [receiverTaint];
      } else if (iterativeMethods.has(methodName) && argumentIndex === 0) {
        callbackArguments = [receiverTaint.property('*')];
      } else {
        return;
      }

      for (const hazard of [...summary.hazards]) {
        const mappedHazard = this.mapTaint(hazard.taint, callbackArguments, Taint.none());
        if (mappedHazard.hasAnyTaint()) {
          this.registerMappedHazard(hazard, mappedHazard, callNode);
        }
      }
    });
  }

  unwrapFunctionNode(node) {
    if (!node) {
      return null;
    }
    if (isFunctionNode(node)) {
      return node;
    }
    if (node.type === 'ArrowFunctionExpression' || node.type === 'FunctionExpression') {
      return node;
    }
    return null;
  }

  getCallMethodName(callNode) {
    const callee = callNode.callee;
    if (!callee || callee.type !== 'MemberExpression') {
      return null;
    }
    if (!callee.computed && callee.property.type === 'Identifier') {
      return callee.property.name;
    }
    if (callee.computed && callee.property.type === 'Literal') {
      return String(callee.property.value);
    }
    return null;
  }

  registerMappedHazard(hazard, mappedTaint, reportNode = hazard.sinkNode) {
    const sources = mappedTaint.collectSources();
    if (sources.size > 0) {
      this.addFinding(hazard.sinkNode, hazard.matcher, sources, reportNode);
      return;
    }

    const summary = this.currentSummary();
    if (summary && mappedTaint.hasAnyOrigin()) {
      summary.hazards.push({
        sinkNode: hazard.sinkNode,
        matcher: hazard.matcher,
        taint: mappedTaint.clone(),
      });
    }
  }

  mapTaint(taint, argTaints, receiverTaint) {
    let result = Taint.none();
    if (!taint) {
      return result;
    }

    taint.sources.forEach((source) => result.sources.add(source));

    for (const origin of taint.origins) {
      const mapped = this.mapOrigin(origin, argTaints, receiverTaint);
      result = result.union(mapped);
    }

    for (const [key, propTaint] of taint.props) {
      result = result.union(Taint.none().withProperty(key, this.mapTaint(propTaint, argTaints, receiverTaint)));
    }

    return result;
  }

  mapOrigin(origin, argTaints, receiverTaint) {
    const parsed = parseOrigin(origin);
    let baseTaint;
    if (parsed.base === 'this') {
      baseTaint = receiverTaint || Taint.none();
    } else if (/^\d+$/.test(parsed.base)) {
      baseTaint = argTaints[Number(parsed.base)] || Taint.none();
    } else {
      baseTaint = Taint.none();
    }

    let current = baseTaint;
    for (const segment of parsed.path) {
      current = current.property(segment);
    }
    return current;
  }

  resolveCalleeFunctions(callNode) {
    const callee = callNode.callee;

    if (isFunctionNode(callee)) {
      return [callee];
    }

    const scope = this.getScope(callNode);

    if (callee.type === 'Identifier') {
      return [...this.resolveIdentifierFunctions(callee.name, scope)];
    }

    if (callee.type === 'MemberExpression' && !callee.computed) {
      return [...this.resolveMemberFunctions(callee, scope)];
    }

    return [];
  }

  resolveIdentifierFunctions(name, scope) {
    const result = new Set();

    for (const fn of this.functionNames.get(name) || []) {
      result.add(fn);
    }

    const variable = scope ? findVariable(scope, name) : null;
    if (variable) {
      for (const def of variable.defs || []) {
        if (def.type === 'FunctionName' && isFunctionNode(def.node)) {
          result.add(def.node);
        }
        if (def.node && def.node.type === 'VariableDeclarator' && def.node.init && isFunctionNode(def.node.init)) {
          result.add(def.node.init);
        }
        if (def.node && def.node.type === 'AssignmentExpression' && isFunctionNode(def.node.right)) {
          result.add(def.node.right);
        }
      }
    }

    return result;
  }

  resolveMemberFunctions(memberNode, scope) {
    const result = new Set();
    const propertyName = memberNode.property.type === 'Identifier' ? memberNode.property.name : null;
    if (!propertyName) {
      return result;
    }

    if (memberNode.object.type === 'ObjectExpression') {
      const fn = this.findObjectMethod(memberNode.object, propertyName);
      if (fn) {
        result.add(fn);
      }
      return result;
    }

    if (memberNode.object.type === 'NewExpression') {
      for (const classNode of this.resolveClassNodes(memberNode.object.callee, scope)) {
        const fn = this.findClassMethod(classNode, propertyName);
        if (fn) {
          result.add(fn);
        }
      }
      return result;
    }

    if (memberNode.object.type !== 'Identifier') {
      return result;
    }

    const objectName = memberNode.object.name;
    for (const fn of this.functionNames.get(`${objectName}.${propertyName}`) || []) {
      result.add(fn);
    }

    const variable = scope ? findVariable(scope, objectName) : null;
    const initializers = this.getDefinitionInitializers(variable);
    for (const initializer of initializers) {
      if (initializer.type === 'ObjectExpression') {
        const fn = this.findObjectMethod(initializer, propertyName);
        if (fn) {
          result.add(fn);
        }
      }
      if (initializer.type === 'NewExpression') {
        for (const classNode of this.resolveClassNodes(initializer.callee, scope)) {
          const fn = this.findClassMethod(classNode, propertyName);
          if (fn) {
            result.add(fn);
          }
        }
      }
    }

    return result;
  }

  resolveClassNodes(callee, scope) {
    const classes = [];
    if (!callee) {
      return classes;
    }
    if (callee.type === 'ClassExpression' || callee.type === 'ClassDeclaration') {
      classes.push(callee);
      return classes;
    }
    if (callee.type !== 'Identifier' || !scope) {
      return classes;
    }

    const classVariable = findVariable(scope, callee.name);
    for (const def of classVariable?.defs || []) {
      if (def.node && (def.node.type === 'ClassDeclaration' || def.node.type === 'ClassExpression')) {
        classes.push(def.node);
      }
      if (def.node && def.node.type === 'VariableDeclarator' && def.node.init && (def.node.init.type === 'ClassExpression' || def.node.init.type === 'ClassDeclaration')) {
        classes.push(def.node.init);
      }
    }

    for (const initializer of this.getDefinitionInitializers(classVariable)) {
      if (initializer.type === 'ClassExpression' || initializer.type === 'ClassDeclaration') {
        classes.push(initializer);
      }
    }

    return classes;
  }

  findClassMethod(classNode, propertyName) {
    if (!classNode || !classNode.body) {
      return null;
    }
    const method = classNode.body.body.find((member) => member.type === 'MethodDefinition' && member.key.type === 'Identifier' && member.key.name === propertyName && member.value);
    return method && method.value ? method.value : null;
  }

  getDefinitionInitializers(variable) {
    const result = [];
    if (!variable) {
      return result;
    }

    for (const def of variable.defs || []) {
      if (def.node && def.node.type === 'VariableDeclarator' && def.node.init) {
        result.push(def.node.init);
      }
    }
    return result;
  }

  findObjectMethod(objectExpression, propertyName) {
    for (const property of objectExpression.properties) {
      if (property.type !== 'Property') {
        continue;
      }
      const key = this.getPatternKey(property);
      if (key !== propertyName) {
        continue;
      }
      if (isFunctionNode(property.value)) {
        return property.value;
      }
    }
    return null;
  }
}

function createTaintRule(ruleOverrides = {}) {
  return {
    meta: {
      type: 'problem',
      docs: {
        description: 'Detects cross-function source-to-sink injection flows with lightweight taint tracking.',
        category: 'Possible Security Vulnerability',
        recommended: false,
        url: 'https://github.com/eslint-community/eslint-plugin-security/blob/main/docs/rules/detect-taint.md',
      },
      schema: [
        {
          anyOf: [
            {
              type: 'object',
              additionalProperties: true,
            },
            {
              type: 'array',
            },
          ],
        },
      ],
      messages: {
        taintedSink: 'Tainted data from {{sources}} reaches {{category}}sink {{sink}} without a recognized sanitizer; validate or sanitize it before this call.',
      },
    },
    create(context) {
      return {
        Program(program) {
          const tracker = new TaintTracker(context, context.options || [], ruleOverrides);
          const findings = tracker.analyze(program);
          for (const finding of findings) {
            context.report({ node: finding.node, message: finding.message });
          }
        },
      };
    },
  };
}

const taintRule = createTaintRule();

module.exports = taintRule;
module.exports.taintRule = taintRule;
module.exports.rule = taintRule;
module.exports.createTaintRule = createTaintRule;
module.exports.TaintTracker = TaintTracker;
module.exports.TaintAnalyzer = TaintTracker;
module.exports.Taint = Taint;
module.exports.Env = Env;
module.exports.normalizeTaintOptions = normalizeTaintOptions;
module.exports.DEFAULT_SOURCES = DEFAULT_SOURCES;
module.exports.DEFAULT_SINKS = DEFAULT_SINKS;
module.exports.DEFAULT_SANITIZERS = DEFAULT_SANITIZERS;
module.exports.trackTaint = function trackTaint(context, program, overrides = {}) {
  const tracker = new TaintTracker(context, context.options || [], overrides);
  return tracker.analyze(program);
};
