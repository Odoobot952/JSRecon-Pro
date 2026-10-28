# JSRecon Pro v2

Automated JavaScript security triage for **authorized** website assessments. Enter a website URL and the tool can inventory same-origin JavaScript assets, fetch source maps when explicitly linked, analyze downloaded code with AST-based rules, perform conservative taint heuristics, and create JSON + interactive HTML reports.

## Important safety model
- You must explicitly authorize each target hostname. The CLI requires `--allow-host example.com` (or a matching subdomain) for live scans.
- Live discovery is same-origin only. Redirects to unapproved hosts are rejected. No crawling of arbitrary links, login bypass, exploitation, payload injection, brute force, or state-changing requests.
- This is a passive assessment helper. Findings are hypotheses, not proof of exploitability. Review them manually and follow your engagement rules.
- The tool does not attempt to exploit XSS or execute downloaded site scripts.

## Requirements
- Python 3.11+
- Node.js 18+ (for AST parsing with bundled parser dependency)
- Network access for live URL scans
- Install dependencies: `npm install`

## Quick start
```bash
# 1) Install the AST parser dependency
npm install

# 2) Scan an explicitly authorized site (hostname must be listed)
python -m jsrecon scan-url https://app.example.com --allow-host app.example.com --out report

# 3) Scan local source
python -m jsrecon scan-dir ./frontend --out report

# 4) Open report/report.html in a browser
```

Optional flags:
```bash
python -m jsrecon scan-url https://app.example.com \
  --allow-host app.example.com \
  --max-assets 80 --timeout 12 --out report
```

Output folder contains:
- `report.json`: machine-readable findings, asset inventory, scan metadata
- `report.html`: self-contained interactive report with search and severity filters

## What it checks
- AST-derived use of `eval`, `new Function`, HTML sinks (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`)
- Heuristic source-to-sink data-flow leads (URL/query/hash/message/storage sources into risky sinks in the same function/file)
- `postMessage` wildcard target origins
- `Math.random` near security-sensitive identifiers
- credential-like literals (redacted evidence)
- linked source-map files and map `sourcesContent` where available
- unsafe password form HTTP actions in downloaded HTML
- inventory of same-origin JavaScript assets and external asset references

## Scope and limitations
- Static taint is intentionally conservative and not a full interprocedural analysis. It does not resolve all imports, framework semantics, sanitizers, or minified bundles perfectly.
- Source-map retrieval is restricted to same-origin URLs and only follows explicit `sourceMappingURL` directives.
- Live scans use GET requests only and enforce a per-host asset cap, byte cap, timeout, and allowlist.
- No scanner can guarantee the absence of vulnerabilities. Treat severity and confidence as triage aids.
