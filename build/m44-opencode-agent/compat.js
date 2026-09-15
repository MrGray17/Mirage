'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');

const target = '/workspace/README.md';
const maxProposalBytes = 64 << 10;
const maxTargetBytes = 4 << 20;
const maxPromptTargetBytes = 48 << 10;

function exactKeys(value, expected) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
}

function unwrapJSON(text) {
  const trimmed = text.trim();
  const fenced = /^```(?:json)?\s*\n?([\s\S]*?)\n?```$/i.exec(trimmed);
  return fenced ? fenced[1].trim() : trimmed;
}

function parseCandidate(text) {
  let value;
  try {
    value = JSON.parse(unwrapJSON(text));
  } catch {
    return null;
  }
  if (!value || (value.name === undefined && value.arguments === undefined)) {
    return null;
  }
  if (!exactKeys(value, ['name', 'arguments']) || value.name !== 'write'
      || !exactKeys(value.arguments, ['content', 'filePath'])
      || value.arguments.filePath !== target
      || typeof value.arguments.content !== 'string'
      || value.arguments.content.includes('\u0000')
      || Buffer.byteLength(value.arguments.content, 'utf8') > maxProposalBytes) {
    throw new Error('OpenCode returned an unsupported structured write proposal');
  }
  return value.arguments.content;
}

function parseOpenCodeWrite(output) {
  const proposals = [];
  for (const line of output.split(/\r?\n/)) {
    if (!line.trim()) continue;
    let event;
    try {
      event = JSON.parse(line);
    } catch {
      continue;
    }
    if (event?.type !== 'text' || typeof event?.part?.text !== 'string') continue;
    const proposal = parseCandidate(event.part.text);
    if (proposal !== null) proposals.push(proposal);
  }
  if (proposals.length !== 1) {
    throw new Error(`OpenCode returned ${proposals.length} supported write proposals; exactly one is required`);
  }
  return proposals[0];
}

function openRegularTarget(flags) {
  const descriptor = fs.openSync(target, flags | fs.constants.O_NOFOLLOW);
  try {
    const info = fs.fstatSync(descriptor);
    if (!info.isFile() || info.nlink !== 1 || info.size > maxTargetBytes) {
      throw new Error('README.md is not a bounded, singly-linked regular file');
    }
    return descriptor;
  } catch (error) {
    fs.closeSync(descriptor);
    throw error;
  }
}

function digestRegularTarget() {
  const descriptor = openRegularTarget(fs.constants.O_RDONLY);
  try {
    return crypto.createHash('sha256').update(fs.readFileSync(descriptor)).digest('hex');
  } finally {
    fs.closeSync(descriptor);
  }
}

function readRegularTargetForPrompt() {
  const descriptor = openRegularTarget(fs.constants.O_RDONLY);
  try {
    const encoded = fs.readFileSync(descriptor);
    if (encoded.length > maxPromptTargetBytes) {
      throw new Error('README.md exceeds the constrained model-input cap');
    }
    const content = new TextDecoder('utf-8', { fatal: true }).decode(encoded);
    if (content.includes('\u0000')) {
      throw new Error('README.md contains NUL and cannot enter the constrained model prompt');
    }
    return content;
  } finally {
    fs.closeSync(descriptor);
  }
}

function buildCompatibilityTask(task, currentContent) {
  if (typeof task !== 'string' || !task.trim()) {
    throw new Error('OpenCode task is required');
  }
  if (typeof currentContent !== 'string'
      || Buffer.byteLength(currentContent, 'utf8') > maxPromptTargetBytes
      || currentContent.includes('\u0000')) {
    throw new Error('README.md cannot enter the constrained model prompt');
  }
  return [
    'MIRAGE constrained OpenCode mode.',
    'Complete the user task by proposing exactly one full replacement of /workspace/README.md.',
    'Do not request a read: the trusted compatibility wrapper has supplied the current file below.',
    'Return exactly one JSON object with no prose and no Markdown fence.',
    'Use this exact structure (the value of content is only the complete final file, never the task wording):',
    '{"name":"write","arguments":{"filePath":"/workspace/README.md","content":"hello"}}',
    'USER TASK:',
    task,
    'CURRENT README CONTENT AS A JSON STRING:',
    JSON.stringify(currentContent),
  ].join('\n');
}

function applyOpenCodeWrite(content) {
  const encoded = Buffer.from(content, 'utf8');
  if (encoded.length > maxProposalBytes) {
    throw new Error('OpenCode write proposal exceeds the compatibility cap');
  }
  const descriptor = openRegularTarget(fs.constants.O_WRONLY);
  try {
    fs.ftruncateSync(descriptor, 0);
    let offset = 0;
    while (offset < encoded.length) {
      offset += fs.writeSync(descriptor, encoded, offset, encoded.length - offset, offset);
    }
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

module.exports = {
  applyOpenCodeWrite,
  buildCompatibilityTask,
  digestRegularTarget,
  parseOpenCodeWrite,
  readRegularTargetForPrompt,
};
