#!/usr/bin/env node
'use strict';
// Rebuilds data/mcp-advisories.json ONLY from public sources. Never hand-add advisories.
// Source 1: AKRENON Security, "MCP Security Vulnerabilities Dataset 2026" (dataset D-001), CC BY 4.0
//   https://data.akrenon.com/mcp-advisories/  (CSV: mcp_advisories.csv, licence: LICENSE.md)
//   Changes made: filtered to npm/PyPI rows that are not withdrawn/excluded; columns renamed/reduced.
// Source 2 (at Action runtime, not stored): OSV.dev API.
const fs = require('fs');
const path = require('path');
const CSV_URL = 'https://data.akrenon.com/mcp-advisories/mcp_advisories.csv';

function parseCsv(text) {
  const rows = []; let row = [], f = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { f += '"'; i++; } else q = false; } else f += c; continue; }
    if (c === '"') q = true; else if (c === ',') { row.push(f); f = ''; }
    else if (c === '\n') { row.push(f); rows.push(row); row = []; f = ''; } else if (c !== '\r') f += c;
  }
  if (f || row.length) { row.push(f); rows.push(row); }
  const [h, ...rest] = rows;
  return rest.filter((r) => r.length > 1).map((r) => Object.fromEntries(h.map((k, i) => [k, r[i] || ''])));
}

function toEntry(r) {
  const e = {
    id: r.ghsa || r.cve || r.osv || r.id,
    aliases: [...new Set([r.id, r.cve, r.ghsa, r.osv, ...r.aliases.split(';')].filter(Boolean))],
    ecosystem: r.ecosystem, package: r.package, severity: r.severity || 'UNKNOWN',
    category: r.category, summary: r.summary, url: r.url, published: r.published,
    source: 'AKRENON MCP Security Vulnerabilities Dataset (CC BY 4.0)',
  };
  const fx = r.fixed.trim();
  if (/[<>=]/.test(fx)) e.affected = fx; else if (/^\d/.test(fx)) e.fixed = fx;
  return e;
}

async function main() {
  const res = await fetch(CSV_URL);
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${CSV_URL}`);
  const rows = parseCsv(await res.text());
  const adv = rows.filter((r) => (r.ecosystem === 'npm' || r.ecosystem === 'PyPI') && r.package && !r.withdrawn && !r.exclude_reason)
    .map(toEntry).sort((a, b) => (a.package + a.id).localeCompare(b.package + b.id));
  if (adv.length < 50) throw new Error(`Only ${adv.length} rows; refusing to overwrite (source format changed?)`);
  const out = {
    generated: new Date().toISOString(),
    sources: [{ name: 'AKRENON Security, MCP Security Vulnerabilities Dataset 2026 (D-001)', url: 'https://data.akrenon.com/mcp-advisories/',
      license: 'CC BY 4.0', license_url: 'https://creativecommons.org/licenses/by/4.0/', changes: 'Filtered to npm/PyPI, non-withdrawn, non-excluded rows; fields reduced.' }],
    count: adv.length, advisories: adv,
  };
  fs.writeFileSync(path.join(__dirname, '..', 'data', 'mcp-advisories.json'), JSON.stringify(out, null, 1) + '\n');
  console.log(`Wrote ${adv.length} advisories`);
}
if (require.main === module) main().catch((e) => { console.error(e); process.exit(1); });
module.exports = { parseCsv, toEntry };
