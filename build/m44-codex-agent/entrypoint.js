#!/usr/bin/env node
'use strict';

const net = require('node:net');
const { spawn } = require('node:child_process');

const socketPath = process.env.MIRAGE_MODEL_SOCKET;
const model = process.env.MIRAGE_MODEL;
const brokerPreflightExit = 78;
if (!socketPath || !model || process.argv.length < 3) {
  process.stderr.write('mirage-codex: broker socket, model, and task are required\n');
  process.exit(64);
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
  process.stderr.write(`mirage-codex: local broker bridge failed: ${error.message}\n`);
  process.exit(70);
});

function failBrokerPreflight(reason) {
  process.stderr.write(`MIRAGE_DIAGNOSTIC_CLASS=BROKER_CONNECT stage=sandbox_broker_preflight reason=${reason}\n`);
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

preflightBroker(() => server.listen({ host: '127.0.0.1', port: 7777 }, () => {
  const task = process.argv.slice(2).join(' ');
  const args = [
    'exec',
    '--ephemeral',
    '--sandbox', 'danger-full-access',
    '--skip-git-repo-check',
    '-c', 'model_provider="mirage"',
    '-c', `model=${JSON.stringify(model)}`,
    '-c', 'model_providers.mirage.name="Mirage Broker"',
    '-c', 'model_providers.mirage.base_url="http://127.0.0.1:7777/v1"',
    '-c', 'model_providers.mirage.env_key="MIRAGE_BROKER_DUMMY"',
    '-c', 'model_providers.mirage.wire_api="responses"',
    task,
  ];
  const child = spawn('/usr/local/bin/codex', args, {
    cwd: '/workspace',
    env: process.env,
    stdio: 'inherit',
  });
  child.on('error', (error) => {
    process.stderr.write(`mirage-codex: Codex failed to start: ${error.message}\n`);
    server.close(() => process.exit(70));
  });
  child.on('exit', (code, signal) => {
    server.close(() => {
      if (signal) {
        process.kill(process.pid, signal);
        return;
      }
      process.exit(code ?? 70);
    });
  });
}));
