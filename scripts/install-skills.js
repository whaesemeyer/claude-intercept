#!/usr/bin/env node
'use strict';

// Shared template: both agents execute the same CLI, against this checkout's
// capture database. Render the invocation for the agent's shell.
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
const quotePosix = value => "'" + value.replaceAll("'", "'\\''") + "'";
const quotePowerShell = value => "'" + value.replaceAll("'", "''") + "'";
// Codex desktop may not inherit the PATH used by the terminal that ran this
// installer. Bind the skill to the verified Node executable used right now.
const cliPath = path.join(root, 'src/cli.js');
const template = fs.readFileSync(path.join(root, 'skill.md'), 'utf8');
function renderSkill(name) {
  const powerShell = process.platform === 'win32' && name === 'codex';
  const cli = powerShell
    ? `& ${quotePowerShell(process.execPath)} ${quotePowerShell(cliPath)}`
    : `${quotePosix(process.execPath)} ${quotePosix(cliPath)}`;
  return template
    .replaceAll('{{CLI}}', () => cli)
    .replaceAll('{{SHELL}}', () => powerShell ? 'powershell' : 'bash')
    .replaceAll('{{SHELL_NOTE}}', () => powerShell
      ? 'On Windows, run these Codex skill commands in PowerShell. The call operator (`&`) invokes the quoted Node executable.'
      : '');
}
const targets = {
  claude: '.claude',
  codex: '.agents',
};
const destinations = (agent === 'both' ? Object.keys(targets) : [agent]).map(name => {
  const agentDir = path.join(os.homedir(), targets[name]);
  const skillsDir = path.join(agentDir, 'skills');
  const dir = path.join(skillsDir, 'intercept');
  return { name, directories: [agentDir, skillsDir, dir], dir, target: path.join(dir, 'SKILL.md') };
});

// Preflight both destinations before overwriting either skill. Refuse links so
// an installer run cannot redirect a write outside the requested skill path.
for (const { directories, dir, target } of destinations) {
  for (const directory of directories) {
    if (!fs.lstatSync(directory, { throwIfNoEntry: false })) {
      try { fs.mkdirSync(directory, { mode: 0o700 }); }
      catch (err) { if (err.code !== 'EEXIST') throw err; }
    }
    if (!fs.lstatSync(directory).isDirectory()) {
      throw new Error(`Skill path is not a regular directory: ${directory}`);
    }
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
    fs.writeFileSync(temporary, renderSkill(name), { mode: 0o600, flag: 'wx' });
    fs.renameSync(temporary, target);
    fs.chmodSync(target, 0o600);
  } finally {
    try { fs.unlinkSync(temporary); } catch (err) {
      if (err.code !== 'ENOENT') throw err;
    }
  }
  console.log(`  ✓ ${name} skill installed → ${target}`);
}
