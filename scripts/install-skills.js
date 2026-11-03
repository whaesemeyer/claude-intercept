#!/usr/bin/env node
'use strict';

// Shared template: both agents execute the same CLI, against this checkout's
// capture database. No shell interpolation of paths (spaces, $, &, quotes).
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { randomBytes } = require('node:crypto');

const agent = process.argv[2];
if (!['claude', 'codex', 'both'].includes(agent) || process.argv.length !== 3) {
  console.error('Usage: node scripts/install-skills.js claude|codex|both');
  process.exit(1);
}
const root = path.resolve(__dirname, '..');
const quote = value => "'" + value.replaceAll("'", "'\\''") + "'";
const cli = `node ${quote(path.join(root, 'src/cli.js'))}`;
const template = fs.readFileSync(path.join(root, 'skill.md'), 'utf8');
const rendered = template.replaceAll('{{CLI}}', () => cli);
const targets = {
  claude: '.claude',
  codex: '.agents',
};
const destinations = (agent === 'both' ? Object.keys(targets) : [agent]).map(name => {
  const dir = path.join(os.homedir(), targets[name], 'skills', 'intercept');
  return { name, dir, target: path.join(dir, 'SKILL.md') };
});

// Preflight both destinations before overwriting either skill. Refuse links so
// an installer run cannot redirect a write outside the requested skill path.
for (const { dir, target } of destinations) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (!fs.lstatSync(dir).isDirectory()) {
    throw new Error(`Skill directory is not a regular directory: ${dir}`);
  }
  fs.chmodSync(dir, 0o700);
  const current = fs.lstatSync(target, { throwIfNoEntry: false });
  if (current && !current.isFile()) {
    throw new Error(`Skill target is not a regular file: ${target}`);
  }
}

for (const { name, dir, target } of destinations) {
  const temporary = path.join(dir, `.SKILL.md.${process.pid}.${randomBytes(6).toString('hex')}`);
  try {
    fs.writeFileSync(temporary, rendered, { mode: 0o600, flag: 'wx' });
    fs.renameSync(temporary, target);
    fs.chmodSync(target, 0o600);
  } finally {
    try { fs.unlinkSync(temporary); } catch (err) {
      if (err.code !== 'ENOENT') throw err;
    }
  }
  console.log(`  ✓ ${name} skill installed → ${target}`);
}
