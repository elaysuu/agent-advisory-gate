'use strict';
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
