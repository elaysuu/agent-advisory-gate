'use strict';
// LIVE test: hits https://api.osv.dev. Skip with AAG_OFFLINE=1.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const fs = require('fs');
const { scan, summaryMarkdown, toSarif } = require('../src/scan');
const curatedFile = path.join(__dirname, '..', 'data', 'mcp-advisories.json');
const fx = (n) => path.join(__dirname, 'fixtures', n);
const qa = process.env.AAG_QA_DIR;
const save = (n, d) => qa && fs.writeFileSync(path.join(qa, n), typeof d === 'string' ? d : JSON.stringify(d, null, 2));

test('vulnerable fixture fails (free) with real GHSA for mcp-remote', { skip: !!process.env.AAG_OFFLINE }, async () => {
  const r = await scan({ root: fx('vulnerable'), tier: 'free', curatedFile });
  save('vulnerable-free.json', r); save('vulnerable-free-summary.md', summaryMarkdown(r));
  assert.strictEqual(r.osvError, null);
  const ids = r.advisories.map((a) => a.id);
  assert.ok(ids.includes('GHSA-6xpm-ggf7-wc3p'), ids.join());
  assert.ok(r.failing > 0);
});
test('vulnerable fixture, pro tier: all severities + fixed versions + SARIF', { skip: !!process.env.AAG_OFFLINE }, async () => {
  const r = await scan({ root: fx('vulnerable'), tier: 'pro', curatedFile });
  save('vulnerable-pro.json', r); save('vulnerable-pro-summary.md', summaryMarkdown(r, 'license valid')); save('vulnerable-pro.sarif', toSarif(r, '1.0.0'));
  const mr = r.advisories.find((a) => a.id === 'GHSA-6xpm-ggf7-wc3p');
  assert.ok(mr.fixed.includes('0.1.16'));
  assert.ok(r.advisories.length >= r.failing - r.rules.length);
});
test('clean fixture passes', { skip: !!process.env.AAG_OFFLINE }, async () => {
  const r = await scan({ root: fx('clean'), tier: 'pro', curatedFile });
  save('clean-pro.json', r); save('clean-pro-summary.md', summaryMarkdown(r));
  assert.strictEqual(r.osvError, null);
  assert.strictEqual(r.advisories.length, 0, JSON.stringify(r.advisories));
  assert.strictEqual(r.failing, 0);
});
test('OSV down => curated map still catches it', async () => {
  const r = await scan({ root: fx('vulnerable'), tier: 'free', curatedFile, fetchImpl: async () => { throw new Error('offline'); } });
  assert.ok(r.osvError);
  assert.ok(r.advisories.some((a) => a.id === 'GHSA-6xpm-ggf7-wc3p'));
});
