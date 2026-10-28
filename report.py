import html, json
from pathlib import Path

def write_reports(report, out_dir):
    out=Path(out_dir); out.mkdir(parents=True,exist_ok=True)
    (out/"report.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    data=json.dumps(report).replace("</","<\\/")
    page=r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>JSRecon Pro Security Report</title>
<style>
:root{color-scheme:dark;font:15px system-ui,sans-serif;background:#10151d;color:#e8edf5}
body{margin:0}header{padding:24px 5vw;background:#171f2b;border-bottom:1px solid #344154}
main{max-width:1200px;margin:auto;padding:24px 5vw}.muted{color:#aab7c8}.cards{display:flex;gap:12px;flex-wrap:wrap}
.card{background:#1a2432;border:1px solid #344154;border-radius:12px;padding:14px 18px;min-width:130px}
.controls{display:flex;gap:10px;flex-wrap:wrap;margin:22px 0}
input,select{background:#121a25;color:#e8edf5;border:1px solid #43536a;border-radius:8px;padding:10px}
.finding{background:#182230;border:1px solid #344154;border-radius:12px;margin:12px 0;padding:16px}
.badge{font-size:12px;font-weight:700;padding:4px 8px;border-radius:6px;background:#344154}
.high,.critical{color:#ff9d9d}.medium{color:#ffd27f}.low{color:#a9d4ff}.info{color:#b9c4d4}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#101720;padding:12px;border-radius:8px}
button{background:#263c55;color:#fff;border:1px solid #526a86;border-radius:8px;padding:9px 12px;cursor:pointer}
</style></head><body><header><h1>JSRecon Pro <small>v2.0.0</small></h1><div id="target" class="muted"></div></header>
<main><div id="summary" class="cards"></div><div class="controls">
<input id="q" placeholder="Search findings, files, evidence…" aria-label="Search">
<select id="sev"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select>
<select id="conf"><option value="">All confidence levels</option><option>high</option><option>medium</option><option>low</option></select>
<button id="export">Export filtered JSON</button></div><section id="findings"></section><h2>Assets</h2><div id="assets" class="muted"></div><h2>Scan errors / skipped items</h2><div id="errors" class="muted"></div><p class="muted" id="disclaimer"></p></main>
<script>
const report=__REPORT__;
document.getElementById('target').textContent=`Mode: ${report.mode} · Target: ${report.target||'(local source)'} · Assets/files: ${report.assets_scanned}`;
const summary=document.getElementById('summary');
[['Findings',report.finding_count],...Object.entries(report.severity_counts).map(([k,v])=>[k,v])].forEach(([k,v])=>{let d=document.createElement('div');d.className='card';d.innerHTML=`<div class="muted">${k}</div><strong style="font-size:24px">${v}</strong>`;summary.appendChild(d)});
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function filtered(){const q=document.getElementById('q').value.toLowerCase(),sev=document.getElementById('sev').value,conf=document.getElementById('conf').value;return report.findings.filter(f=>(!sev||f.severity===sev)&&(!conf||f.confidence===conf)&&JSON.stringify(f).toLowerCase().includes(q))}
function render(){const fs=filtered(),root=document.getElementById('findings');root.innerHTML=`<h2>Findings (${fs.length})</h2>`+fs.map(f=>`<article class="finding"><div><span class="badge ${esc(f.severity)}">${esc(f.severity.toUpperCase())}</span> <span class="muted">${esc(f.id)} · confidence: ${esc(f.confidence)} · ${esc(f.validation_status)}</span></div><h3>${esc(f.title)}</h3><div class="muted">${esc(f.file)}:${esc(f.line)}:${esc(f.column||1)}</div><p>${esc(f.description||'')}</p><pre>${esc(f.evidence||'')}</pre><p><b>Remediation:</b> ${esc(f.remediation||'')}</p><button data-copy="${esc(f.fingerprint||'')}">Copy finding ID</button></article>`).join('')||'<p>No findings match these filters.</p>';root.querySelectorAll('button[data-copy]').forEach(b=>b.onclick=()=>navigator.clipboard?.writeText(b.dataset.copy));}
['q','sev','conf'].forEach(id=>document.getElementById(id).addEventListener(id==='q'?'input':'change',render));
document.getElementById('export').onclick=()=>{const blob=new Blob([JSON.stringify(filtered(),null,2)],{type:'application/json'}),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='jsrecon-filtered-findings.json';a.click();URL.revokeObjectURL(a.href)};
document.getElementById('assets').innerHTML=report.assets.map(a=>`<div>${esc(a.kind)} · ${esc(a.url||a.file)} · ${esc(a.bytes)} bytes</div>`).join('')||'None';
document.getElementById('errors').innerHTML=report.errors.map(e=>`<div>${esc(e.file)}: ${esc(e.error)}</div>`).join('')||'None';
document.getElementById('disclaimer').textContent=report.disclaimer;render();
</script></body></html>""".replace("__REPORT__",data)
    (out/"report.html").write_text(page,encoding="utf-8")
    return out/"report.json",out/"report.html"
