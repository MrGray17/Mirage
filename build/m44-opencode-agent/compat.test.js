'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { buildCompatibilityTask, parseOpenCodeWrite } = require('./compat.js');

function event(text) {
  return JSON.stringify({ type: 'text', part: { text } });
}

test('accepts one exact README write from OpenCode JSON output', () => {
  const output = [
    JSON.stringify({ type: 'step_start' }),
    event('```json\n{"name":"write","arguments":{"content":"safe\\n","filePath":"/workspace/README.md"}}\n```'),
    JSON.stringify({ type: 'step_finish' }),
  ].join('\n');
  assert.equal(parseOpenCodeWrite(output), 'safe\n');
});

test('builds a bounded explicit write-only task with the current README', () => {
  const prompt = buildCompatibilityTask('Update the heading', '# Current\n');
  assert.match(prompt, /proposing exactly one full replacement/);
  assert.match(prompt, /USER TASK:\nUpdate the heading/);
  assert.match(prompt, /CURRENT README CONTENT AS A JSON STRING:\n"# Current\\n"/);
  assert.match(prompt, /"filePath":"\/workspace\/README.md"/);
});

test('rejects unsafe compatibility prompt inputs', () => {
  assert.throws(() => buildCompatibilityTask('', '# Current\n'), /task is required/);
  assert.throws(() => buildCompatibilityTask('task', 'bad\u0000content'), /cannot enter/);
  assert.throws(() => buildCompatibilityTask('task', 'x'.repeat((48 << 10) + 1)), /cannot enter/);
});

for (const [name, proposal] of [
  ['wrong path', { name: 'write', arguments: { content: 'x', filePath: '/workspace/other.txt' } }],
  ['wrong tool', { name: 'edit', arguments: { content: 'x', filePath: '/workspace/README.md' } }],
  ['extra field', { name: 'write', arguments: { content: 'x', filePath: '/workspace/README.md', extra: true } }],
  ['NUL content', { name: 'write', arguments: { content: 'x\u0000y', filePath: '/workspace/README.md' } }],
]) {
  test(`rejects ${name}`, () => {
    assert.throws(() => parseOpenCodeWrite(event(JSON.stringify(proposal))), /unsupported/);
  });
}

test('rejects missing and duplicate proposals', () => {
  assert.throws(() => parseOpenCodeWrite(event('ordinary prose')), /0 supported/);
  const proposal = event('{"name":"write","arguments":{"content":"x","filePath":"/workspace/README.md"}}');
  assert.throws(() => parseOpenCodeWrite(`${proposal}\n${proposal}`), /2 supported/);
});

test('rejects oversized content', () => {
  const proposal = { name: 'write', arguments: { content: 'x'.repeat((64 << 10) + 1), filePath: '/workspace/README.md' } };
  assert.throws(() => parseOpenCodeWrite(event(JSON.stringify(proposal))), /unsupported/);
});
