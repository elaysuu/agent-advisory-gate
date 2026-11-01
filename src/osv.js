'use strict';
const { satisfies, cmp } = require('./semver');
const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN = 'https://api.osv.dev/v1/vulns/';
const SEV_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, MODERATE: 2, LOW: 1, UNKNOWN: 0 };

function normSeverity(s) {
  const u = String(s || '').toUpperCase();
  if (u === 'MODERATE') return 'MEDIUM';
  return SEV_ORDER[u] !== undefined ? u : 'UNKNOWN';
}

function fixedVersions(vuln, pkg) {
  const out = new Set();
  for (const a of vuln.affected || []) {
    if (a.package && a.package.name !== pkg) continue;
    for (const r of a.ranges || []) for (const e of r.events || []) if (e.fixed) out.add(e.fixed);
  }
  return [...out].sort(cmp);
}

function severityOf(vuln) {
  if (vuln.database_specific && vuln.database_specific.severity) return normSeverity(vuln.database_specific.severity);
  for (const a of vuln.affected || []) {
    if (a.ecosystem_specific && a.ecosystem_specific.severity) return normSeverity(a.ecosystem_specific.severity);
  }
  if (/^MAL-/.test(vuln.id)) return 'CRITICAL';
  return 'UNKNOWN';
}

async function postJson(url, body, fetchImpl) {
  const r = await fetchImpl(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error(`OSV HTTP ${r.status}`);
  return r.json();
}

// packages: [{ecosystem, pkg, version}] (npm/PyPI only). Sends ONLY name+ecosystem(+version) to OSV.
async function queryOsv(packages, { fetchImpl = fetch } = {}) {
  const pk = packages.filter((p) => p.ecosystem === 'npm' || p.ecosystem === 'PyPI');
  if (!pk.length) return new Map();
  const queries = pk.map((p) => ({ package: { name: p.pkg, ecosystem: p.ecosystem }, ...(p.pinned ? { version: p.version } : {}) }));
  const res = await postJson(OSV_BATCH, { queries }, fetchImpl);
  const ids = new Set();
  (res.results || []).forEach((r) => (r.vulns || []).forEach((v) => ids.add(v.id)));
  const details = new Map();
  await Promise.all([...ids].map(async (id) => {
    const r = await fetchImpl(OSV_VULN + encodeURIComponent(id));
    if (r.ok) details.set(id, await r.json());
  }));
  const out = new Map();
  pk.forEach((p, i) => {
    const list = [];
    for (const v of (res.results[i] && res.results[i].vulns) || []) {
      const d = details.get(v.id) || v;
      if (d.withdrawn) continue;
      const fixed = fixedVersions(d, p.pkg);
      list.push({
        id: d.id, aliases: d.aliases || [], summary: d.summary || (d.details || '').slice(0, 160),
        severity: severityOf(d), fixed, url: `https://osv.dev/vulnerability/${d.id}`, source: 'OSV',
        // Unpinned query returns history; mark whether a fix exists (latest is then likely safe).
        hasFix: fixed.length > 0,
      });
    }
    out.set(`${p.ecosystem}:${p.pkg}`, list);
  });
  return out;
}

// Curated map entries: {id, aliases, ecosystem, package, severity, affected|fixed, summary, url, source, category}
function matchCurated(entries, p) {
  const name = p.ecosystem === 'PyPI' ? p.pkg.toLowerCase().replace(/[-_.]+/g, '-') : p.pkg;
  const out = [];
  for (const e of entries) {
    const en = e.ecosystem === 'PyPI' ? e.package.toLowerCase().replace(/[-_.]+/g, '-') : e.package;
    if (e.ecosystem !== p.ecosystem || en !== name) continue;
    let applies, hasFix = false;
    if (e.category === 'malicious_package') applies = true;
    else if (e.affected) { hasFix = /</.test(e.affected); applies = p.pinned ? satisfies(p.version, e.affected) : !hasFix; }
    else if (e.fixed) { hasFix = true; applies = p.pinned ? cmp(p.version, e.fixed) < 0 : false; }
    else applies = true; // no version info => all versions
    if (!applies) continue;
    out.push({ id: e.id, aliases: e.aliases || [], summary: e.summary, severity: normSeverity(e.severity),
      fixed: e.fixed ? [e.fixed] : [], url: e.url, source: e.source || 'curated', hasFix });
  }
  return out;
}

module.exports = { queryOsv, matchCurated, normSeverity, severityOf, fixedVersions, SEV_ORDER, OSV_BATCH };
