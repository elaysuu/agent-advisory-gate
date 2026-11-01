'use strict';
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
