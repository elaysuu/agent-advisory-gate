'use strict';
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { extractPackage, parseJsonc } = require('../src/parse');
const { satisfies } = require('../src/semver');
const { verifyLicense } = require('../src/license');
const { configRules } = require('../src/rules');
const { parseConfigFile } = require('../src/parse');

test('extracts npm/uvx/pipx/docker packages', () => {
  assert.deepStrictEqual(extractPackage('npx', ['-y', '@scope/srv@1.2.3']), { ecosystem: 'npm', pkg: '@scope/srv', version: '1.2.3' });
  assert.deepStrictEqual(extractPackage('npx', ['-y', 'mcp-remote']), { ecosystem: 'npm', pkg: 'mcp-remote', version: null });
  assert.deepStrictEqual(extractPackage('uvx', ['mcp-server-git==0.6.2']), { ecosystem: 'PyPI', pkg: 'mcp-server-git', version: '0.6.2' });
  assert.deepStrictEqual(extractPackage('uvx', ['--from', 'pkg==1.0', 'cmd']), { ecosystem: 'PyPI', pkg: 'pkg', version: '1.0' });
  assert.deepStrictEqual(extractPackage('pipx', ['run', 'mcp-x']), { ecosystem: 'PyPI', pkg: 'mcp-x', version: null });
  assert.deepStrictEqual(extractPackage('docker', ['run', '-i', '--rm', '-e', 'T', 'ghcr.io/github/github-mcp-server:v0.1']), { ecosystem: 'docker', pkg: 'ghcr.io/github/github-mcp-server', version: 'v0.1' });
  assert.strictEqual(extractPackage('node', ['server.js']), null);
});
test('jsonc + ranges', () => {
  assert.deepStrictEqual(parseJsonc('{// c\n"a": "http://x", /* b */ "b": [1,],}'), { a: 'http://x', b: [1] });
  assert.ok(satisfies('1.2.0', '>= 1.0.1, < 1.31.4'));
  assert.ok(!satisfies('1.31.4', '>= 1.0.1, < 1.31.4'));
});
test('pro config rules on hygiene fixture', () => {
  const p = parseConfigFile(path.join(__dirname, 'fixtures/hygiene/claude_desktop_config.json'), path.join(__dirname, 'fixtures/hygiene'));
  const rules = p.servers.flatMap(configRules).map((r) => `${r.server}:${r.rule}`).sort();
  assert.deepStrictEqual(rules, ['gh:AAG001-unpinned', 'gh:AAG003-plaintext-secret', 'latest:AAG002-floating', 'plain:AAG004-insecure-transport']);
  assert.ok(!JSON.stringify(p.servers.flatMap(configRules)).includes('fixture-not-a-real'), 'secret value never echoed');
});

const resp = (status, json) => async () => ({ status, ok: status < 400, json: async () => json });
test('license: valid, cancelled, refunded, invalid, unreachable', async () => {
  const pid = 'TESTPRODUCT==';
  const ok = { success: true, purchase: { refunded: false, subscription_cancelled_at: null, subscription_ended_at: null, subscription_failed_at: null } };
  assert.strictEqual((await verifyLicense('K', { productId: pid, fetchImpl: resp(200, ok) })).tier, 'pro');
  for (const f of ['subscription_cancelled_at', 'subscription_ended_at', 'subscription_failed_at']) {
    assert.strictEqual((await verifyLicense('K', { productId: pid, fetchImpl: resp(200, { success: true, purchase: { [f]: '2026-10-01T00:00:00Z' } }) })).tier, 'free');
  }
  assert.strictEqual((await verifyLicense('K', { productId: pid, fetchImpl: resp(200, { success: true, purchase: { refunded: true } }) })).tier, 'free');
  assert.strictEqual((await verifyLicense('K', { productId: pid, fetchImpl: resp(404, { success: false }) })).tier, 'free');
  const down = await verifyLicense('K', { productId: pid, fetchImpl: async () => { throw new TypeError('fetch failed'); } });
  assert.strictEqual(down.tier, 'free'); assert.match(down.reason, /unreachable/);
  let sent;
  await verifyLicense('K', { productId: pid, fetchImpl: async (u, o) => { sent = o.body.toString(); return { status: 200, json: async () => ok }; } });
  assert.match(sent, /increment_uses_count=false/); assert.match(sent, /product_id=TESTPRODUCT/);
  assert.strictEqual((await verifyLicense('K')).tier, 'free', 'placeholder product id => free');
});
