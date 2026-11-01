'use strict';
const fs = require('fs');
const path = require('path');

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
