# Agent Advisory Gate

**`npm audit` for your AI agent's tools.** A GitHub Action that fails the PR when your repo's MCP config
(`mcp.json`, `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`) points at an
MCP server with a published security advisory.

```yaml
- uses: actions/checkout@v4
- uses: elaysuu/agent-advisory-gate@v1
  # with: { license-key: ${{ secrets.AAG_LICENSE }} }   # optional, Pro
```

Example: `npx -y mcp-remote@0.1.15` → ❌ **CRITICAL GHSA-6xpm-ggf7-wc3p** (CVE-2025-6514, OS command injection).
Full workflow: [`examples/agent-advisory-gate.yml`](examples/agent-advisory-gate.yml).

## What it reads
- `command` + `args` for `npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `npm exec` (npm), `uvx`, `uv tool run`, `pipx run` (PyPI), `docker`/`podman run` (image).
- `url` entries (remote servers) for transport checks.
- Extra files via `config-paths` (comma/newline separated). JSONC comments are fine.

## Free vs Pro
| | Free | Pro ($9/mo or $79/yr) |
|---|---|---|
| OSV.dev live lookup (npm, PyPI) + bundled MCP advisory map | ✅ | ✅ |
| Fails on CRITICAL / HIGH | ✅ | ✅ |
| All severities (MEDIUM / LOW), `fail-on` threshold | – | ✅ |
| Fix-version hints | – | ✅ |
| Config-safety rules: unpinned `npx -y pkg`, `@latest`/ranges, plaintext secrets in `env`/headers, remote `http://` servers | – | ✅ |
| SARIF for GitHub code scanning | – | ✅ |
| Job summary + PR annotations | ✅ | ✅ |

## Pro

**[Get Agent Advisory Gate Pro on Gumroad](https://setrov.gumroad.com/l/zdojns)**: $9/month or $79/year.

Setup:
1. Buy the membership. Gumroad emails you a license key.
2. In your repo, add it as a secret named `AAG_LICENSE` (Settings → Secrets and variables → Actions).
3. Pass it to the action:
   ```yaml
   - uses: elaysuu/agent-advisory-gate@v1
     with:
       license-key: ${{ secrets.AAG_LICENSE }}
   ```
An invalid, expired, or unreachable license never fails your build. The action falls back to the free tier and says why in the job summary.

Unpinned packages (`npx -y foo`) run the latest release, so for those the gate only reports advisories with **no fixed
version yet**. Pin versions to get exact matching.

## Privacy
- **OSV.dev** receives only package names, ecosystems and pinned versions. No file contents, env values, URLs or repo names.
- **Gumroad** receives only your license key and our product id (`increment_uses_count=false`), and only when `license-key` is set.
- Nothing else leaves the runner. Secret values found by the Pro rules are never printed.
- If Gumroad is unreachable the action **falls back to free tier** — licensing never fails your build.

## Data & attribution
- [OSV.dev](https://osv.dev) (queried live; includes the GitHub Advisory Database and PyPA data).
- `data/mcp-advisories.json` is derived from **AKRENON Security, *MCP Security Vulnerabilities Dataset 2026*, dataset D-001**,
  https://data.akrenon.com/mcp-advisories/ , licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
  Changes: filtered to npm/PyPI, non-withdrawn, non-excluded rows; fields reduced. Rebuilt daily by
  [`refresh-data.yml`](.github/workflows/refresh-data.yml). No advisory is hand-written.
- Listing a package does not mean every version is affected. Always check the linked advisory.

## Develop
```sh
node --test test/          # includes a live OSV test; AAG_OFFLINE=1 to skip
npm run build              # bundles src/ -> dist/ with ncc (no runtime npm install)
npm run refresh-data
```
MIT licensed (code). See [LICENSE](LICENSE) for data terms.

## Also available as

- VS Code / Open VSX extension: https://open-vsx.org/extension/elaysuu/agent-package-advisory
- RapidAPI (HTTP API): https://rapidapi.com/Elayosetrov/api/agent-package-advisory-check
- Apify actor: https://apify.com/crimson_goby/osv-package-checker
