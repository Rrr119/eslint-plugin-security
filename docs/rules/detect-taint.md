# Detects cross-function source-to-sink injection flows (`security/detect-taint`)

<!-- end auto-generated rule header -->

This rule adds lightweight, file-local interprocedural taint tracking to the plugin.

The older rules intentionally match syntax close to a dangerous call. They remain unchanged and keep their current behavior. `detect-taint` additionally follows untrusted data through variables, string composition, object properties, destructuring, returns, and small wrapper functions.

## Rule details

The rule tracks three configurable matcher groups:

- `sources`: untrusted entry points such as `req.query`, `req.body`, `req.params`, `request.*`, Koa `ctx.*`, `process.argv`, and `process.env`.
- `sinks`: dangerous calls such as `eval`, `new Function`, `child_process.exec`, SQL `query`/`execute`/`raw`, and common `fs` APIs.
- `sanitizers`: functions that remove taint, such as `sanitize`, `escape`, `encodeURIComponent`, `parseInt`, `Number`, `DOMPurify.sanitize`, and SQL escaping helpers.

Matching is deliberately syntactic and scope-aware where possible. A string matcher can be an exact access path, a bare function name, or use `*` as a single-path-segment wildcard.

Examples of **incorrect** code for this rule:

```js
function run(command) {
  require('child_process').exec(command);
}

app.post('/run', (req, res) => {
  run(req.body.command);
});
```

```js
const buildCommand = (name) => `ls -l ${name}`;
const run = (command) => childProcess.exec(command);

run(buildCommand(req.query.path));
```

Examples of **correct** code for this rule:

```js
function run(command) {
  require('child_process').exec(command);
}

run('ls -l');
```

```js
function run(command) {
  require('child_process').exec(command);
}

run(sanitizeCommand(req.body.command));
```

## Options

The rule accepts one options object. All matcher keys also accept singular aliases (`source`, `sink`, and `sanitizer`).

```js
'security/detect-taint': ['error', {
  sources: ['socket.data', { name: 'rpc.getInput', label: 'RPC input' }],
  sinks: [
    'dangerExec#0',
    { name: 'db.rawQuery', args: [0], category: 'sql-injection' },
  ],
  sanitizers: ['normalizeCommand', { name: 'allowlistCommand' }],
  useDefaults: true,
  propagateThroughUnknownCalls: true,
  followCrossFunction: true,
}]
```

- `sources`: additional or replacement source matchers.
- `sinks`: additional or replacement sink matchers. Sink objects accept `args`, `arguments`, `indices`, or `all`.
- `sanitizers`: calls whose return value is considered safe.
- `useDefaults`: set to `false` to use only the matchers supplied in configuration.
- `followCrossFunction`: defaults to `true`.
- `propagateThroughUnknownCalls`: defaults to `true`; unknown function calls propagate taint from tainted arguments/receiver unless they match a sanitizer.
- `reportLocation`: use `sink` (the default) to report the final dangerous call, or `call` to report the cross-function call site that supplied tainted data.

This rule is not in `recommended` yet because taint rules benefit from project-specific source and sanitizer configuration. Enable it explicitly and extend the matchers for your framework and data-access layer.
