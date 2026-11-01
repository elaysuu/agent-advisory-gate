'use strict';
const fs = require('fs');
const path = require('path');
const { scan, summaryMarkdown, toSarif } = require('./scan');
const { verifyLicense } = require('./license');
const VERSION = '1.0.0';
// Read the map from the repo's data/ at runtime (not bundled) so the daily refresh commit takes effect immediately.
const DATA_PARTS = ['data', 'mcp-advisories.json'];
const dataFile = () => path.resolve(__dirname, '..', DATA_PARTS.join(path.sep));

const input = (n) => (process.env[`INPUT_${n.replace(/ /g, '_').toUpperCase()}`] || '').trim();
const esc = (s) => String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
function setOutput(k, v) { if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `${k}=${v}\n`); }

async function run() {
  const root = process.env.GITHUB_WORKSPACE || process.cwd();
  const key = input('license-key');
  if (key) console.log(`::add-mask::${key}`);
  const lic = await verifyLicense(key);
  const failOn = input('fail-on').toUpperCase() || undefined;
  const r = await scan({ root, tier: lic.tier, failOn: lic.tier === 'pro' ? failOn : (failOn === 'CRITICAL' ? 'CRITICAL' : undefined),
    configPaths: input('config-paths').split(/[\n,]/).map((s) => s.trim()).filter(Boolean),
    curatedFile: dataFile() });
  const md = summaryMarkdown(r, key ? lic.reason : '');
  if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, md + '\n');
  console.log(md);
  for (const a of r.advisories) console.log(`::${a.severity === 'CRITICAL' || a.severity === 'HIGH' ? 'error' : 'warning'} file=${a.file},line=${a.line},title=${esc(a.id)}::${esc(`${a.package} (${a.server}): ${a.summary}`)}`);
  for (const x of r.rules) console.log(`::warning file=${x.file},line=${x.line},title=${x.rule}::${esc(x.message)}`);
  if (lic.tier === 'pro') {
    const out = input('sarif-file') || 'agent-advisory-gate.sarif';
    fs.writeFileSync(path.resolve(root, out), JSON.stringify(toSarif(r, VERSION), null, 2));
    setOutput('sarif-file', out);
  }
  setOutput('tier', r.tier); setOutput('advisories', r.advisories.length); setOutput('failing', r.failing);
  if (r.failing) { console.log(`::error::${r.failing} finding(s) at or above ${r.minSeverity}`); process.exitCode = 1; }
}
run().catch((e) => { console.log(`::error::agent-advisory-gate crashed: ${esc(e.stack || e)}`); process.exitCode = 1; });
