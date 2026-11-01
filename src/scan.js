'use strict';
const fs = require('fs');
const path = require('path');
const { findConfigs, parseConfigFile } = require('./parse');
const { queryOsv, matchCurated, SEV_ORDER } = require('./osv');
const { configRules } = require('./rules');
const { isExact } = require('./semver');

function loadCurated(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')).advisories || []; } catch { return []; }
}

async function scan({ root, configPaths = [], tier = 'free', failOn, curatedFile, fetchImpl = fetch }) {
  const files = findConfigs(root, configPaths);
  const parsed = files.map((f) => parseConfigFile(f, root));
  const servers = parsed.flatMap((p) => p.servers);
  const pkgs = servers.filter((s) => s.pkg).map((s) => ({ ...s, pinned: isExact(s.version) }));
  const uniq = [...new Map(pkgs.map((p) => [`${p.ecosystem}:${p.pkg}@${p.pinned ? p.version : ''}`, p])).values()];

  let osv = new Map(), osvError = null;
  try { osv = await queryOsv(uniq, { fetchImpl }); } catch (e) { osvError = e.message; }
  const curated = loadCurated(curatedFile);

  const advisories = [];
  for (const p of pkgs) {
    const fromOsv = (osv.get(`${p.ecosystem}:${p.pkg}`) || []).filter((v) => p.pinned || !v.hasFix);
    const merged = [...fromOsv];
    const seen = new Set(fromOsv.flatMap((v) => [v.id, ...v.aliases]));
    for (const c of matchCurated(curated, p)) {
      if ([c.id, ...c.aliases].some((x) => seen.has(x))) continue;
      merged.push(c); [c.id, ...c.aliases].forEach((x) => seen.add(x));
    }
    for (const v of merged) advisories.push({ ...v, server: p.name, file: p.file, line: p.line,
      package: p.pkg, ecosystem: p.ecosystem, version: p.pinned ? p.version : null });
  }
  const minSev = failOn || (tier === 'pro' ? 'LOW' : 'HIGH');
  const visible = advisories.filter((a) => tier === 'pro' || SEV_ORDER[a.severity] >= SEV_ORDER.HIGH);
  const rules = tier === 'pro' ? servers.flatMap(configRules) : [];
  const failing = [...visible, ...rules].filter((a) => SEV_ORDER[a.severity] >= SEV_ORDER[minSev]);
  return {
    tier, minSeverity: minSev, files: parsed.map((p) => ({ file: p.file, error: p.error, servers: p.servers.length })),
    servers: servers.map((s) => ({ name: s.name, file: s.file, ecosystem: s.ecosystem, package: s.pkg, version: s.version, url: s.url ? new URL(s.url).host : null })),
    advisories: visible, hiddenBelowHigh: advisories.length - visible.length, rules, failing: failing.length, osvError,
  };
}

function summaryMarkdown(r, licenseNote) {
  const L = [];
  L.push(`## Agent Advisory Gate — ${r.failing ? '❌ failing' : '✅ passing'}`);
  L.push(`Tier: **${r.tier}**${licenseNote ? ` (${licenseNote})` : ''} · fail threshold: **${r.minSeverity}** · configs: ${r.files.length} · MCP servers: ${r.servers.length}`);
  if (r.osvError) L.push(`> ⚠️ OSV lookup failed (${r.osvError}); only the bundled advisory map was used.`);
  for (const f of r.files) if (f.error) L.push(`> ⚠️ ${f.file}: ${f.error}`);
  if (r.advisories.length) {
    L.push('', '| Severity | Advisory | Server | Package | Fixed in | Summary |', '|---|---|---|---|---|---|');
    for (const a of r.advisories) {
      const fixed = r.tier === 'pro' ? (a.fixed.join(', ') || '—') : '(Pro)';
      L.push(`| ${a.severity} | [${a.id}](${a.url}) | ${a.server} (${a.file}) | ${a.package}${a.version ? '@' + a.version : ''} | ${fixed} | ${String(a.summary || '').replace(/\|/g, '/').slice(0, 120)} |`);
    }
  } else L.push('', 'No known advisories for the MCP servers found.');
  if (r.rules.length) {
    L.push('', '### Config safety (Pro)', '| Severity | Rule | Server | Detail |', '|---|---|---|---|');
    for (const x of r.rules) L.push(`| ${x.severity} | ${x.rule} | ${x.server} (${x.file}) | ${x.message.replace(/\|/g, '/')} |`);
  }
  if (r.tier !== 'pro') L.push('', `_Free tier shows CRITICAL/HIGH advisories${r.hiddenBelowHigh ? ` (${r.hiddenBelowHigh} lower-severity hidden)` : ''}. Pro adds all severities, config-safety rules, SARIF and fix versions._`);
  L.push('', '<sub>Data: [OSV.dev](https://osv.dev) and the AKRENON Security MCP Security Vulnerabilities Dataset (CC BY 4.0).</sub>');
  return L.join('\n');
}

const SARIF_LEVEL = { CRITICAL: 'error', HIGH: 'error', MEDIUM: 'warning', LOW: 'note', UNKNOWN: 'warning' };
function toSarif(r, version) {
  const results = [], rules = new Map();
  for (const a of r.advisories) {
    rules.set(a.id, { id: a.id, shortDescription: { text: String(a.summary || a.id).slice(0, 200) }, helpUri: a.url,
      properties: { 'security-severity': { CRITICAL: '9.5', HIGH: '7.5', MEDIUM: '5.0', LOW: '2.0' }[a.severity] || '5.0', tags: ['security', 'mcp'] } });
    results.push({ ruleId: a.id, level: SARIF_LEVEL[a.severity], message: { text: `${a.package}${a.version ? '@' + a.version : ''} (MCP server "${a.server}") has ${a.id}: ${a.summary}${a.fixed.length ? `. Fixed in ${a.fixed.join(', ')}` : ''}` },
      locations: [{ physicalLocation: { artifactLocation: { uri: a.file }, region: { startLine: a.line } } }] });
  }
  for (const x of r.rules) {
    rules.set(x.rule, { id: x.rule, shortDescription: { text: x.rule }, properties: { tags: ['mcp', 'config'] } });
    results.push({ ruleId: x.rule, level: SARIF_LEVEL[x.severity], message: { text: x.message },
      locations: [{ physicalLocation: { artifactLocation: { uri: x.file }, region: { startLine: x.line } } }] });
  }
  return { version: '2.1.0', $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{ tool: { driver: { name: 'agent-advisory-gate', version, informationUri: 'https://github.com/elaysuu/agent-advisory-gate', rules: [...rules.values()] } }, results }] };
}

module.exports = { scan, summaryMarkdown, toSarif, loadCurated };
