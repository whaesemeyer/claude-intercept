#!/usr/bin/env node
'use strict';

// Shared template: both agents execute the same CLI, against this checkout's
// capture database. No shell interpolation of paths (spaces, $, &, quotes).
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

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
for (const name of agent === 'both' ? Object.keys(targets) : [agent]) {
  const dir = path.join(os.homedir(), targets[name], 'skills', 'intercept');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'SKILL.md'), rendered);
  console.log(`  ✓ ${name} skill installed → ${path.join(dir, 'SKILL.md')}`);
}
