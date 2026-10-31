# JSX-Ray Pro v2.0

Local-first JavaScript security research analyzer for **authorized codebases and local labs**.

## v2 features
1. **Acorn AST parsing** (syntax-aware analysis rather than regex-only scanning).
2. **Source-to-sink hints** for browser-controlled sources and HTML/dynamic-code sinks.
3. **DOM XSS pattern checks**, including `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, message handlers, and `eval`/`Function`.
4. **Source map inspection** for local map references and embedded `sourcesContent`.

> Important: flow analysis is heuristic and mostly same-file/local. It is not a complete interprocedural taint engine, and findings are not proof of exploitability. Manually validate every result.

## Requirements
- Python is not required for the AST engine.
- Node.js 18+ and npm.
- Termux: `pkg install nodejs`; Kali/Parrot: `sudo apt install nodejs npm`.
- Optional browser check: Playwright + Chromium. Termux can use the static analyzer and manual browser inspection; Playwright browser support varies by device.

## Install
```bash
unzip jsxray_pro_v2.zip
cd jsxray_pro_v2
npm install
```

## Analyze a local project
```bash
node ast_analyzer.js /path/to/authorized/project out/report.json
```
The report is JSON and includes findings, source-map status, and limitations.

## Local training lab
Serve the bundled lab on loopback only:
```bash
cd lab
node -e "require('http').createServer((q,s)=>{require('fs').readFile('index.html',(e,d)=>{s.end(d)})}).listen(8765,'127.0.0.1')"
```
Open `http://127.0.0.1:8765`. The page includes a safe `textContent` example and an intentionally unsafe `innerHTML` example for local analysis.

## Optional Playwright check
In another terminal:
```bash
npm install
npx playwright install chromium
node browser_check.js
```
The script is hard-coded to the loopback lab and rejects non-loopback hosts.

## Test the analyzer
```bash
node ast_analyzer.js lab out/lab-report.json
```
Expected: findings for the intentional `innerHTML` sink and a source map-free report.

## Safety scope
No remote crawling, payload spraying, credential collection, exploit delivery, or arbitrary target browser automation. Use only on code you own or are authorized to assess.
