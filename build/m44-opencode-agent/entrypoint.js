#!/usr/bin/env node
'use strict';

const net = require('node:net');
const { spawn } = require('node:child_process');
const {
  applyOpenCodeWrite,
  buildCompatibilityTask,
  digestRegularTarget,
  parseOpenCodeWrite,
  readRegularTargetForPrompt,
} = require('/usr/local/lib/mirage-opencode-compat.js');

const socketPath = process.env.MIRAGE_MODEL_SOCKET;
const model = process.env.MIRAGE_MODEL;
const brokerPreflightExit = 78;
const maxCapturedOutput = 256 << 10;

if (!socketPath || !model || process.argv.length !== 3 || !process.argv[2].trim()) {
  process.stderr.write('mirage-opencode: broker socket, model, and one task are required\n');
  process.exit(64);
}

function failBrokerPreflight(reason) {
  process.stderr.write(
    `MIRAGE_DIAGNOSTIC_CLASS=BROKER_CONNECT stage=sandbox_broker_preflight reason=${reason}\n`,
  );
  process.exit(brokerPreflightExit);
}

function preflightBroker(onSuccess) {
  const broker = net.createConnection({ path: socketPath });
  let response = '';
  let finished = false;
  const timeout = setTimeout(() => {
    broker.destroy();
    failBrokerPreflight('timeout');
  }, 5000);
  const finish = (error) => {
    if (finished) return;
    finished = true;
    clearTimeout(timeout);
    if (error) {
      failBrokerPreflight(error.code || 'connect_error');
      return;
    }
    if (!response.startsWith('HTTP/1.1 204 ')) {
      failBrokerPreflight('unexpected_response');
      return;
    }
    onSuccess();
  };
  broker.on('connect', () => {
    broker.write('GET /_mirage/broker-preflight HTTP/1.1\r\nHost: mirage\r\nConnection: close\r\n\r\n');
  });
  broker.on('data', (chunk) => {
    if (response.length + chunk.length > 4096) {
      broker.destroy();
      finish({ code: 'response_limit' });
      return;
    }
    response += chunk.toString('utf8');
  });
  broker.on('end', () => finish(null));
  broker.on('error', (error) => finish(error));
}

function trustedConfig() {
  return JSON.stringify({
    $schema: 'https://opencode.ai/config.json',
    model: `mirage/${model}`,
    autoupdate: false,
    share: 'disabled',
    snapshot: false,
    subagent_depth: 0,
    provider: {
      mirage: {
        name: 'MIRAGE Broker',
        npm: '@ai-sdk/openai-compatible',
        options: {
          apiKey: 'broker-scoped-no-secret',
          baseURL: 'http://127.0.0.1:7777/v1',
        },
        models: {
          [model]: {
            name: 'MIRAGE-bound model',
            limit: { context: 32768, output: 2048 },
          },
        },
      },
    },
    permission: {
      '*': 'deny',
      read: 'allow',
      edit: 'allow',
      glob: 'allow',
      grep: 'allow',
      list: 'allow',
      bash: 'deny',
      task: 'deny',
      external_directory: 'deny',
      webfetch: 'deny',
      websearch: 'deny',
      lsp: 'deny',
      skill: 'deny',
      question: 'deny',
    },
  });
}

preflightBroker(() => {
  let initialTargetDigest;
  let compatibilityTask;
  try {
    initialTargetDigest = digestRegularTarget();
    compatibilityTask = buildCompatibilityTask(process.argv[2], readRegularTargetForPrompt());
  } catch (error) {
    process.stderr.write(`mirage-opencode: initial README validation failed: ${error.message}\n`);
    process.exit(65);
  }
  const server = net.createServer((client) => {
    const broker = net.createConnection({ path: socketPath });
    client.on('error', () => broker.destroy());
    broker.on('error', () => client.destroy());
    client.pipe(broker);
    broker.pipe(client);
  });
  server.maxConnections = 8;
  server.on('error', (error) => {
    process.stderr.write(`mirage-opencode: local broker bridge failed: ${error.message}\n`);
    process.exit(70);
  });
  server.listen({ host: '127.0.0.1', port: 7777 }, () => {
    const captured = [];
    let capturedBytes = 0;
    let capturedOverflow = false;
    let settled = false;
    const child = spawn(
      '/usr/local/bin/opencode',
      [
        '--pure',
        'run',
        '--auto',
        '--format',
        'json',
        '--model',
        `mirage/${model}`,
        '--agent',
        'build',
        compatibilityTask,
      ],
      {
        cwd: '/workspace',
        env: {
          HOME: process.env.HOME,
          PATH: process.env.PATH,
          MIRAGE_MODEL: model,
          OPENCODE_CONFIG_CONTENT: trustedConfig(),
          OPENCODE_DISABLE_AUTOUPDATE: 'true',
          OPENCODE_DISABLE_CLAUDE_CODE: 'true',
          OPENCODE_DISABLE_DEFAULT_PLUGINS: 'true',
          OPENCODE_DISABLE_LSP_DOWNLOAD: 'true',
          OPENCODE_DISABLE_MODELS_FETCH: 'true',
          OPENCODE_DISABLE_TERMINAL_TITLE: 'true',
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    child.stdout.on('data', (chunk) => {
      process.stdout.write(chunk);
      if (capturedBytes >= maxCapturedOutput) {
        capturedOverflow = true;
        return;
      }
      const remaining = maxCapturedOutput - capturedBytes;
      captured.push(chunk.subarray(0, remaining));
      capturedBytes += Math.min(chunk.length, remaining);
      if (chunk.length > remaining) capturedOverflow = true;
    });
    child.stderr.pipe(process.stderr);
    child.on('error', (error) => {
      if (settled) return;
      settled = true;
      process.stderr.write(`mirage-opencode: OpenCode failed to start: ${error.message}\n`);
      server.close(() => process.exit(70));
    });
    // `close` fires after stdout/stderr close, so the structured proposal is
    // complete before the compatibility parser observes it.
    child.on('close', (code, signal) => {
      if (settled) return;
      settled = true;
      server.close(() => {
        if (signal) {
          process.kill(process.pid, signal);
          return;
        }
        if (code !== 0) {
          process.exit(code ?? 70);
          return;
        }
        try {
          const finalTargetDigest = digestRegularTarget();
          if (finalTargetDigest === initialTargetDigest) {
            if (capturedOverflow) {
              throw new Error('OpenCode output exceeded the compatibility cap');
            }
            const content = parseOpenCodeWrite(Buffer.concat(captured).toString('utf8'));
            applyOpenCodeWrite(content);
            process.stderr.write('mirage-opencode: applied one constrained README write proposal\n');
          }
        } catch (error) {
          process.stderr.write(`mirage-opencode: compatibility write rejected: ${error.message}\n`);
          process.exit(65);
          return;
        }
        process.exit(0);
      });
    });
  });
});
