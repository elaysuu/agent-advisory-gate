/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ({

/***/ 724:
/***/ ((module) => {


// Gumroad license verification.
// Docs (checked 2026-11-01): https://gumroad.com/help/article/76-license-keys
//   POST https://api.gumroad.com/v2/licenses/verify, no OAuth needed.
//   Params: product_id (required for products created on/after 2023-01-09), license_key,
//           increment_uses_count ("true"/"false", optional, default "true").
//   Response: { success, uses, purchase: { refunded, disputed, chargebacked,
//           subscription_ended_at, subscription_cancelled_at, subscription_failed_at, ... } }
//   "If one of these fields is not null, you can disable the license and terminate access."
//   Invalid key => 404 with { success:false, message }.
const GUMROAD_VERIFY_URL = 'https://api.gumroad.com/v2/licenses/verify';
// Gumroad product: Agent Advisory Gate Pro (https://setrov.gumroad.com/l/zdojns)
const GUMROAD_PRODUCT_ID = 'T7DBQBWWCKR32ph9driJvQ==';

async function verifyLicense(key, { fetchImpl = fetch, productId = GUMROAD_PRODUCT_ID, timeoutMs = 8000 } = {}) {
  if (!key) return { tier: 'free', reason: 'no license-key input' };
  if (productId.startsWith('REPLACE_')) return { tier: 'free', reason: 'product_id not configured in this build' };
  const body = new URLSearchParams({ product_id: productId, license_key: key, increment_uses_count: 'false' });
  let res, json;
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), timeoutMs);
    res = await fetchImpl(GUMROAD_VERIFY_URL, { method: 'POST', body, signal: ctl.signal,
      headers: { 'content-type': 'application/x-www-form-urlencoded' } });
    clearTimeout(t);
    json = await res.json();
  } catch (e) {
    // Fail OPEN to free tier: never break the user's build because of licensing.
    return { tier: 'free', reason: `license server unreachable (${e.name || 'error'}); running free tier` };
  }
  if (res.status >= 500) return { tier: 'free', reason: `license server error ${res.status}; running free tier` };
  if (!json || !json.success) return { tier: 'free', reason: 'license key not valid for this product' };
  const p = json.purchase || {};
  for (const f of ['subscription_cancelled_at', 'subscription_ended_at', 'subscription_failed_at']) {
    if (p[f]) return { tier: 'free', reason: `membership inactive (${f})` };
  }
  if (p.refunded || p.chargebacked || p.disputed) return { tier: 'free', reason: 'purchase refunded/disputed' };
  return { tier: 'pro', reason: 'license valid' };
}

module.exports = { verifyLicense, GUMROAD_PRODUCT_ID, GUMROAD_VERIFY_URL };


/***/ }),

/***/ 359:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


const { satisfies, cmp } = __nccwpck_require__(383);
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


/***/ }),

/***/ 328:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


const fs = __nccwpck_require__(896);
const path = __nccwpck_require__(928);

const DEFAULT_PATHS = ['mcp.json', '.mcp.json', '.cursor/mcp.json', '.vscode/mcp.json', 'claude_desktop_config.json'];

function findConfigs(root, extra = []) {
  const out = [];
  for (const p of [...DEFAULT_PATHS, ...extra]) {
    const full = path.resolve(root, p);
    if (fs.existsSync(full) && fs.statSync(full).isFile() && !out.includes(full)) out.push(full);
  }
  return out;
}

// Tolerates JSONC comments / trailing commas (VS Code style).
function parseJsonc(text) {
  let s = '', inStr = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inStr) { s += c; if (c === '\\') { s += text[++i] || ''; } else if (c === '"') inStr = false; continue; }
    if (c === '"') { inStr = true; s += c; continue; }
    if (c === '/' && text[i + 1] === '/') { while (i < text.length && text[i] !== '\n') i++; s += '\n'; continue; }
    if (c === '/' && text[i + 1] === '*') { i += 2; while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i++; i++; continue; }
    s += c;
  }
  return JSON.parse(s.replace(/,\s*([}\]])/g, '$1'));
}

function lineOf(text, needle) {
  const idx = text.indexOf(JSON.stringify(needle));
  return idx < 0 ? 1 : text.slice(0, idx).split('\n').length;
}

function splitNpmSpec(spec) {
  // @scope/name@1.2.3 | name@1.2.3 | name
  const at = spec.lastIndexOf('@');
  if (at > 0) return { pkg: spec.slice(0, at), version: spec.slice(at + 1) };
  return { pkg: spec, version: null };
}
function splitPySpec(spec) {
  const m = spec.match(/^([A-Za-z0-9_.\-\[\]]+?)\s*(==|@)\s*(.+)$/);
  if (m) return { pkg: m[1].replace(/\[.*\]$/, ''), version: m[3] };
  const n = spec.match(/^([A-Za-z0-9_.\-]+)/);
  return { pkg: n ? n[1] : spec, version: null };
}

const NPM_FLAGS_WITH_VALUE = new Set(['-p', '--package', '--registry', '--cache', '-c', '--call']);
function extractPackage(command, args = []) {
  const base = path.basename(String(command || '')).replace(/\.(cmd|exe)$/, '');
  const a = (args || []).map(String);
  if (['npx', 'bunx'].includes(base) || ((base === 'pnpm' || base === 'yarn') && a[0] === 'dlx') || (base === 'npm' && a[0] === 'exec')) {
    const rest = ['pnpm', 'yarn', 'npm'].includes(base) ? a.slice(1) : a;
    for (let i = 0; i < rest.length; i++) {
      const x = rest[i];
      if (x === '--') continue;
      if (x === '-p' || x === '--package') return { ecosystem: 'npm', ...splitNpmSpec(rest[i + 1] || '') };
      if (x.startsWith('--package=')) return { ecosystem: 'npm', ...splitNpmSpec(x.slice(10)) };
      if (NPM_FLAGS_WITH_VALUE.has(x)) { i++; continue; }
      if (x.startsWith('-')) continue;
      return { ecosystem: 'npm', ...splitNpmSpec(x) };
    }
  }
  if (base === 'uvx' || (base === 'uv' && a[0] === 'tool' && a[1] === 'run') || (base === 'pipx' && a[0] === 'run')) {
    const rest = base === 'uvx' ? a : base === 'uv' ? a.slice(2) : a.slice(1);
    for (let i = 0; i < rest.length; i++) {
      const x = rest[i];
      if (x === '--from' || x === '--spec') return { ecosystem: 'PyPI', ...splitPySpec(rest[i + 1] || '') };
      if (x.startsWith('--from=')) return { ecosystem: 'PyPI', ...splitPySpec(x.slice(7)) };
      if (['--python', '--with', '--index-url', '-p', '--index'].includes(x)) { i++; continue; }
      if (x.startsWith('-')) continue;
      return { ecosystem: 'PyPI', ...splitPySpec(x) };
    }
  }
  if (base === 'docker' || base === 'podman') {
    const i = a.indexOf('run');
    if (i >= 0) {
      for (let j = i + 1; j < a.length; j++) {
        const x = a[j];
        if (['-e', '--env', '-v', '--volume', '--name', '-p', '--network', '--env-file', '-w', '--user', '--mount'].includes(x)) { j++; continue; }
        if (x.startsWith('-')) continue;
        const m = x.match(/^(.+?)(?::([^:/]+))?(?:@sha256:[a-f0-9]+)?$/);
        return { ecosystem: 'docker', pkg: m[1], version: m[2] || null };
      }
    }
  }
  return null;
}

function parseConfigFile(file, root) {
  const text = fs.readFileSync(file, 'utf8');
  const rel = path.relative(root, file) || file;
  let json;
  try { json = parseJsonc(text); } catch (e) { return { file: rel, error: `Invalid JSON: ${e.message}`, servers: [] }; }
  const map = json.mcpServers || json.servers || (json.mcp && json.mcp.servers) || {};
  const servers = [];
  for (const [name, s] of Object.entries(map)) {
    if (!s || typeof s !== 'object') continue;
    const ext = s.command ? extractPackage(s.command, s.args) : null;
    servers.push({
      name, file: rel, line: lineOf(text, name),
      command: s.command || null, args: s.args || [], env: s.env || {}, headers: s.headers || {},
      url: s.url || s.serverUrl || null, type: s.type || null,
      ecosystem: ext ? ext.ecosystem : null, pkg: ext ? ext.pkg : null, version: ext ? ext.version : null,
    });
  }
  return { file: rel, servers };
}

module.exports = { DEFAULT_PATHS, findConfigs, parseConfigFile, extractPackage, parseJsonc, splitNpmSpec, splitPySpec };


/***/ }),

/***/ 224:
/***/ ((module) => {


// Pro config-safety rules. Never prints secret values.
const SECRET_KEY = /(token|secret|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|auth|credential)/i;
const SECRET_VAL = [/^gh[pousr]_[A-Za-z0-9]{20,}/, /^github_pat_/, /^sk-[A-Za-z0-9_-]{16,}/, /^xox[abprs]-/, /^AKIA[0-9A-Z]{16}$/, /^AIza[0-9A-Za-z_-]{30,}/, /^glpat-/];
const isRef = (v) => /^\$\{?[A-Za-z_][A-Za-z0-9_:]*\}?$/.test(v) || /^\$\{(env|input):/.test(v) || v === '' || /^<.*>$/.test(v);

function configRules(s) {
  const f = [];
  const add = (rule, severity, message) => f.push({ rule, severity, message, server: s.name, file: s.file, line: s.line });
  if (s.ecosystem === 'npm' || s.ecosystem === 'PyPI') {
    if (!s.version) add('AAG001-unpinned', 'MEDIUM', `${s.pkg} runs without a pinned version; every run can pull a new, unreviewed release. Pin e.g. ${s.pkg}@<version>.`);
    else if (/^(latest|next|\*|x)$/i.test(s.version) || /^[\^~><]/.test(s.version)) add('AAG002-floating', 'MEDIUM', `${s.pkg}@${s.version} is a floating tag/range; pin an exact version.`);
  }
  if (s.ecosystem === 'docker' && (!s.version || s.version === 'latest')) add('AAG002-floating', 'LOW', `Docker image ${s.pkg} uses ${s.version ? ':latest' : 'no tag'}; pin a tag or digest.`);
  const scan = (obj, where) => {
    for (const [k, v] of Object.entries(obj || {})) {
      const val = String(v);
      if (isRef(val)) continue;
      if (SECRET_VAL.some((r) => r.test(val)) || (SECRET_KEY.test(k) && val.length >= 8 && !/\s/.test(val))) {
        add('AAG003-plaintext-secret', 'HIGH', `${where} "${k}" looks like a plaintext secret committed to the repo. Use \${env:${k}} / an input / a secret store.`);
      }
    }
  };
  scan(s.env, 'env');
  scan(s.headers, 'header');
  (s.args || []).forEach((a) => { if (SECRET_VAL.some((r) => r.test(String(a)))) add('AAG003-plaintext-secret', 'HIGH', 'A command argument looks like a plaintext token.'); });
  if (s.url && /^http:\/\//i.test(s.url) && !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:|\/|$)/i.test(s.url)) {
    add('AAG004-insecure-transport', 'HIGH', `Remote MCP server over plain http (${new URL(s.url).host}); traffic and tokens are unencrypted. Use https.`);
  }
  return f;
}
module.exports = { configRules };


/***/ }),

/***/ 734:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


const fs = __nccwpck_require__(896);
const path = __nccwpck_require__(928);
const { findConfigs, parseConfigFile } = __nccwpck_require__(328);
const { queryOsv, matchCurated, SEV_ORDER } = __nccwpck_require__(359);
const { configRules } = __nccwpck_require__(224);
const { isExact } = __nccwpck_require__(383);

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


/***/ }),

/***/ 383:
/***/ ((module) => {


// Minimal, dependency-free version comparison (semver-ish + PEP 440-ish numeric parts).
function parts(v) {
  const m = String(v).trim().replace(/^v/, '').split(/[-+]/)[0];
  return m.split('.').map((x) => parseInt(x, 10) || 0);
}
function cmp(a, b) {
  const pa = parts(a), pb = parts(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}
// Range like ">= 1.0.1, < 1.31.4" or "<0.6.3" or "=1.2.3"
function satisfies(version, range) {
  return String(range).split(',').map((s) => s.trim()).filter(Boolean).every((c) => {
    const m = c.match(/^(>=|<=|>|<|==|=)?\s*(.+)$/);
    if (!m) return false;
    const r = cmp(version, m[2]);
    switch (m[1] || '=') {
      case '>=': return r >= 0; case '<=': return r <= 0;
      case '>': return r > 0; case '<': return r < 0;
      default: return r === 0;
    }
  });
}
const isExact = (v) => !!v && /^v?\d+(\.\d+)*([-.+][0-9A-Za-z.]+)?$/.test(v);
module.exports = { cmp, satisfies, isExact };


/***/ }),

/***/ 896:
/***/ ((module) => {

module.exports = require("fs");

/***/ }),

/***/ 928:
/***/ ((module) => {

module.exports = require("path");

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __nccwpck_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		var threw = true;
/******/ 		try {
/******/ 			__webpack_modules__[moduleId](module, module.exports, __nccwpck_require__);
/******/ 			threw = false;
/******/ 		} finally {
/******/ 			if(threw) delete __webpack_module_cache__[moduleId];
/******/ 		}
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/compat */
/******/ 	
/******/ 	if (typeof __nccwpck_require__ !== 'undefined') __nccwpck_require__.ab = __dirname + "/";
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};

const fs = __nccwpck_require__(896);
const path = __nccwpck_require__(928);
const { scan, summaryMarkdown, toSarif } = __nccwpck_require__(734);
const { verifyLicense } = __nccwpck_require__(724);
const VERSION = '1.0.1';
// Read the map from the repo's data/ at runtime (not bundled) so the daily refresh commit takes effect immediately.
const DATA_PARTS = (/* unused pure expression or super */ null && (['data', 'mcp-advisories.json']));
const dataFile = () => __nccwpck_require__.ab + "mcp-advisories.json";

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

module.exports = __webpack_exports__;
/******/ })()
;