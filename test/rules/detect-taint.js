'use strict';

const RuleTester = require('eslint').RuleTester;
const ruleName = 'detect-taint';
const rule = require(`../../rules/${ruleName}`);

const tester = new RuleTester({
  languageOptions: {
    ecmaVersion: 2023,
    sourceType: 'commonjs',
  },
});

tester.run(ruleName, rule, {
  valid: [
    "eval('literal')",
    `
    function run(command) {
      require('child_process').exec(command);
    }
    run('ls -l');
    `,
    `
    function run(command) {
      require('child_process').exec(command);
    }
    run(sanitizeCommand(req.query.command));
    `,
    `
    function run(command) {
      require('child_process').exec(escape(command));
    }
    run(req.query.command);
    `,
    `
    function run(options) {
      require('child_process').exec(options.command);
    }
    run({ command: 'ls -l', unrelated: req.query.unrelated });
    `,
    {
      code: `
      function sink(value) {
        customDanger(value);
      }
      sink(safeInput());
      `,
      options: [
        {
          useDefaults: false,
          sources: ['untrustedInput'],
          sinks: ['customDanger'],
        },
      ],
    },
    {
      code: `
      function sink(value) {
        customDanger(clean(value));
      }
      sink(untrustedInput());
      `,
      options: [
        {
          useDefaults: false,
          sources: ['untrustedInput'],
          sinks: ['customDanger'],
          sanitizers: ['clean'],
        },
      ],
    },
  ],

  invalid: [
    {
      code: 'eval(req.query.code)',
      errors: [{ message: /Tainted data from req\.query[\s\S]*eval/ }],
    },
    {
      code: `
      function run(command) {
        require('child_process').exec(command);
      }
      run(req.body.command);
      `,
      errors: [{ message: /req\.body[\s\S]*child_process\.exec/, line: 3 }],
    },
    {
      code: `
      function outer(value) {
        return inner(value);
      }
      function inner(value) {
        eval(value);
      }
      outer(req.query.code);
      `,
      errors: [{ message: /req\.query[\s\S]*eval/, line: 6 }],
    },
    {
      code: `
      function run(options) {
        require('child_process').exec(options.command);
      }
      run({ command: req.params.id });
      `,
      errors: [{ message: /req\.params[\s\S]*child_process\.exec/, line: 3 }],
    },
    {
      code: `
      const childProcess = require('child_process');
      const run = (command) => childProcess.exec(\`ls \${command}\`);
      run(req.query.path);
      `,
      errors: [{ message: /req\.query/ }],
    },
    {
      code: `
      function sink(value) {
        customDanger(value);
      }
      sink(getInput());
      `,
      options: [
        {
          useDefaults: false,
          sources: ['getInput'],
          sinks: ['customDanger'],
        },
      ],
      errors: [{ message: /getInput[\s\S]*customDanger/ }],
    },
    {
      code: `
      const handler = (req) => {
        Promise.resolve(req.query.code).then((code) => eval(code));
      };
      handler(request);
      `,
      errors: [{ message: /req\.query[\s\S]*eval/, line: 3 }],
    },
    {
      code: `
      class CommandRunner {
        run(command) {
          require('child_process').exec(command);
        }
      }
      new CommandRunner().run(req.body.command);
      `,
      errors: [{ message: /req\.body[\s\S]*child_process\.exec/, line: 4 }],
    },
    {
      code: `
      import { exec } from 'node:child_process';
      function run(command) {
        exec(command);
      }
      run(req.query.command);
      `,
      languageOptions: {
        ecmaVersion: 2023,
        sourceType: 'module',
      },
      errors: [{ message: /req\.query[\s\S]*node:child_process\.exec|child_process\.exec/, line: 4 }],
    },
  ],
});
