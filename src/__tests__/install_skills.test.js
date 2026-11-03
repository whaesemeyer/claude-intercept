'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const ROOT = path.resolve(__dirname, '../..');

function fixture(t) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'intercept-install-'));
  t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const home = path.join(tmp, 'home');
  fs.mkdirSync(home);
  const bin = path.join(home, 'test-bin');
  fs.mkdirSync(bin);
  for (const command of ['npm', 'sudo', 'ln']) {
    fs.writeFileSync(path.join(bin, command), '#!/bin/sh\necho "unexpected installer side effect" >&2\nexit 97\n', { mode: 0o755 });
  }
  return { tmp, home };
}
function install(home, args = [], root = ROOT) {
  return spawnSync('bash', [path.join(root, 'install.sh'), '--skills-only', ...args], {
    env: { ...process.env, HOME: home, PATH: `${path.join(home, 'test-bin')}:${process.env.PATH}` }, encoding: 'utf8', timeout: 15000,
  });
}
function skill(home, agent) {
  return path.join(home, agent === 'codex' ? '.agents' : '.claude', 'skills/intercept/SKILL.md');
}

test('default installs discoverable skills for both agents without dependencies or sudo', t => {
  const { home } = fixture(t);
  const result = install(home);
  assert.equal(result.status, 0, result.stderr);
  for (const agent of ['claude', 'codex']) {
    const text = fs.readFileSync(skill(home, agent), 'utf8');
    assert.match(text, /^---\nname: intercept\ndescription: .+\n---\n/);
    assert.ok(!text.includes('{{CLI}}'));
    assert.equal(fs.statSync(skill(home, agent)).mode & 0o777, 0o600);
    assert.equal(fs.statSync(path.dirname(skill(home, agent))).mode & 0o777, 0o700);
  }
  assert.equal(fs.readFileSync(skill(home, 'codex'), 'utf8'), fs.readFileSync(skill(home, 'claude'), 'utf8'));
});

for (const agent of ['claude', 'codex']) {
  test(`${agent}-only install leaves the other agent untouched and is repeatable`, t => {
    const { home } = fixture(t);
    const other = skill(home, agent === 'claude' ? 'codex' : 'claude');
    fs.mkdirSync(path.dirname(other), { recursive: true });
    fs.writeFileSync(other, 'existing custom skill');
    for (let i = 0; i < 2; i++) {
      const result = install(home, ['--agent', agent]);
      assert.equal(result.status, 0, result.stderr);
      assert.ok(fs.existsSync(skill(home, agent)));
      assert.equal(fs.readFileSync(other, 'utf8'), 'existing custom skill');
    }
  });
}

test('invalid or missing agent and unknown flags fail before writing skills', t => {
  const { home } = fixture(t);
  for (const args of [['--agent', 'typo'], ['--agent'], ['--unknown']]) {
    const result = install(home, args);
    assert.notEqual(result.status, 0);
    assert.ok(!fs.existsSync(skill(home, 'claude')));
    assert.ok(!fs.existsSync(skill(home, 'codex')));
  }
});

test('refuses a symlinked skill target without changing the destination', t => {
  const { home } = fixture(t);
  const outside = path.join(home, 'outside.txt');
  fs.writeFileSync(outside, 'keep');
  const target = skill(home, 'codex');
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.symlinkSync(outside, target);
  const result = install(home);
  assert.notEqual(result.status, 0);
  assert.equal(fs.readFileSync(outside, 'utf8'), 'keep');
  assert.ok(!fs.existsSync(skill(home, 'claude')));
});

test('full installer uses the lockfile without dependency lifecycle scripts', t => {
  const { home, tmp } = fixture(t);
  const root = path.join(tmp, 'repo');
  fs.mkdirSync(path.join(root, 'scripts'), { recursive: true });
  fs.mkdirSync(path.join(root, 'src'));
  for (const file of ['install.sh', 'skill.md', 'scripts/install-skills.js']) {
    fs.copyFileSync(path.join(ROOT, file), path.join(root, file));
  }
  fs.writeFileSync(path.join(root, 'src/cli.js'), '#!/usr/bin/env node\n');
  fs.writeFileSync(path.join(home, 'test-bin/npm'),
    '#!/bin/sh\nprintf "%s\\n" "$@" > "$HOME/npm-args"\n', { mode: 0o755 });

  const result = spawnSync('bash', [path.join(root, 'install.sh'), '--agent', 'codex'], {
    env: { ...process.env, HOME: home, PATH: `${path.join(home, 'test-bin')}:${process.env.PATH}` },
    encoding: 'utf8', timeout: 15000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(fs.readFileSync(path.join(home, 'npm-args'), 'utf8').trim().split('\n'),
    ['ci', '--ignore-scripts']);
  assert.ok(fs.existsSync(skill(home, 'codex')));
  for (const dir of ['captures', 'certs']) {
    assert.equal(fs.statSync(path.join(root, dir)).mode & 0o777, 0o700);
  }
});

test('rendered CLI command works from another directory with shell metacharacters in install path', t => {
  const { home, tmp } = fixture(t);
  const root = path.join(tmp, "repo space ' & $HOME `false`");
  fs.mkdirSync(path.join(root, 'scripts'), { recursive: true });
  fs.mkdirSync(path.join(root, 'src'));
  for (const file of ['install.sh', 'skill.md', 'scripts/install-skills.js']) {
    fs.copyFileSync(path.join(ROOT, file), path.join(root, file));
  }
  fs.writeFileSync(path.join(root, 'src/cli.js'), 'console.log(JSON.stringify(process.argv.slice(2)))');
  const result = install(home, ['--agent', 'codex'], root);
  assert.equal(result.status, 0, result.stderr);
  const text = fs.readFileSync(skill(home, 'codex'), 'utf8');
  const command = text.split('\n').find(line => line.startsWith('node ') && line.endsWith(' status --json'));
  assert.ok(command, 'skill provides runnable status command');
  const run = spawnSync('bash', ['-c', command], { cwd: home, encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  assert.deepEqual(JSON.parse(run.stdout), ['status', '--json']);
});
