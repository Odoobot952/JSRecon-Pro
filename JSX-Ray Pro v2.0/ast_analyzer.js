#!/usr/bin/env node
'use strict';
// Local source analyzer. Parses syntax with Acorn; findings are heuristic, not proof of exploitability.
const fs = require('fs'), path = require('path'), acorn = require('acorn');
const ROOT = path.resolve(process.argv[2] || '.');
const OUT = path.resolve(process.argv[3] || 'out/ast-report.json');
const EXT = new Set(['.js','.mjs','.cjs','.jsx']);
const SOURCE = /(location(?:\.href|\.search|\.hash)?|document\.URL|document\.referrer|URLSearchParams|\.searchParams|event\.data|messageEvent\.data)/;
const SINK = /(innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval|Function)/;
const findings = [], sourceMaps = [];
function walk(n, visit, parent=null) {
  if (!n || typeof n !== 'object') return;
  if (typeof n.type === 'string') visit(n,parent);
  for (const [k,v] of Object.entries(n)) {
    if (k === 'loc' || k === 'start' || k === 'end') continue;
    if (Array.isArray(v)) v.forEach(x => walk(x,visit,n));
    else if (v && typeof v === 'object') walk(v,visit,n);
  }
}
function textOf(n, src) { return src.slice(n.start, n.end); }
function add(file, line, severity, rule, message, snippet='') {
  findings.push({file:path.relative(ROOT,file), line, severity, rule, message, snippet:snippet.slice(0,240)});
}
function analyze(file) {
  const src=fs.readFileSync(file,'utf8');
  const mapRe=/\/\/[#@]\s*sourceMappingURL=([^\s]+)/g; let m;
  while((m=mapRe.exec(src))) {
    const ref=m[1]; let status='reference-only', mapFile=null, embeddedSources=0;
    if (!/^https?:\/\//i.test(ref) && !ref.startsWith('data:')) {
      mapFile=path.resolve(path.dirname(file),ref);
      if (mapFile.startsWith(path.resolve(path.dirname(file))+path.sep) && fs.existsSync(mapFile)) {
        try {
          const data=JSON.parse(fs.readFileSync(mapFile,'utf8'));
          embeddedSources=Array.isArray(data.sourcesContent)?data.sourcesContent.filter(Boolean).length:0;
          status='local-map-found';
          if (embeddedSources) add(file,src.slice(0,m.index).split('\n').length,'info','SOURCEMAP_EMBEDDED_SOURCE',
            `Source map embeds ${embeddedSources} source file(s); review for accidental source disclosure.`,ref);
        } catch { status='map-invalid-or-unreadable'; }
      }
    } else if (ref.startsWith('data:')) status='inline-data-map';
    sourceMaps.push({file:path.relative(ROOT,file),reference:ref,status,embeddedSources});
  }
  let ast;
  try { ast=acorn.parse(src,{ecmaVersion:'latest',sourceType:'unambiguous',locations:true,allowHashBang:true}); }
  catch(e) { add(file,e.loc?.line||1,'low','PARSE_ERROR',`Could not parse file: ${e.message}`); return; }
  const vars=new Map();
  walk(ast,(n)=>{
    if(n.type==='VariableDeclarator' && n.id.type==='Identifier' && n.init) {
      const init=textOf(n.init,src);
      vars.set(n.id.name,{source:SOURCE.test(init),expr:init});
    }
  });
  walk(ast,(n)=>{
    const line=n.loc?.start?.line||1;
    if(n.type==='CallExpression') {
      const callee=textOf(n.callee,src);
      if(/\beval$/.test(callee) || /\bFunction$/.test(callee))
        add(file,line,'high','DYNAMIC_CODE_EXECUTION',`Dynamic code execution via ${callee}; validate whether input can be controlled.`,textOf(n,src));
      if(/document\.write/.test(callee))
        add(file,line,'high','HTML_INJECTION_SINK','document.write writes markup into the document.',textOf(n,src));
      if(/insertAdjacentHTML/.test(callee))
        add(file,line,'high','HTML_INJECTION_SINK','insertAdjacentHTML parses the supplied string as HTML.',textOf(n,src));
      if(n.arguments.some(a=>SOURCE.test(textOf(a,src)) || (a.type==='Identifier' && vars.get(a.name)?.source)))
        add(file,line,'high','SOURCE_TO_SINK_HINT','Potential untrusted source reaches a sensitive call argument in this expression.',textOf(n,src));
    }
    if(n.type==='AssignmentExpression') {
      const lhs=textOf(n.left,src), rhs=textOf(n.right,src);
      if(/(?:\.innerHTML|\.outerHTML)$/.test(lhs))
        add(file,line,'high','HTML_INJECTION_SINK',`${lhs} parses assigned content as HTML.`,textOf(n,src));
      if(SOURCE.test(rhs) || (n.right.type==='Identifier' && vars.get(n.right.name)?.source))
        add(file,line,'medium','UNTRUSTED_DATA_ASSIGNMENT','Assignment appears to use a browser-controlled or message-controlled source.',textOf(n,src));
      if(/(?:\.innerHTML|\.outerHTML)$/.test(lhs) && (SOURCE.test(rhs) || (n.right.type==='Identifier' && vars.get(n.right.name)?.source)))
        add(file,line,'critical','POSSIBLE_DOM_XSS_FLOW','Potential source-to-HTML-sink flow detected in the same assignment.',textOf(n,src));
    }
    if(n.type==='MemberExpression') {
      const member=textOf(n,src);
      if(/\.innerHTML$|\.outerHTML$/.test(member))
        add(file,line,'medium','HTML_SINK_USAGE','HTML parsing DOM property referenced; inspect surrounding data flow.',member);
    }
    if(n.type==='CallExpression' && /addEventListener/.test(textOf(n.callee,src)) && n.arguments[0]?.value==='message')
      add(file,line,'medium','MESSAGE_HANDLER','Message event handler found; validate origin and message schema.',textOf(n,src));
    if(n.type==='Literal' && typeof n.value==='string' && /(?:api[_-]?key|secret|token)\s*[:=]\s*['"][A-Za-z0-9_\-]{12,}/i.test(n.value))
      add(file,line,'medium','POSSIBLE_SECRET','String resembles a hardcoded credential; verify and rotate if real.',n.value);
  });
}
function filesUnder(dir) {
  for(const ent of fs.readdirSync(dir,{withFileTypes:true})) {
    if(['node_modules','.git','.venv','dist','build'].includes(ent.name)) continue;
    const p=path.join(dir,ent.name);
    if(ent.isDirectory()) filesUnder(p);
    else if(EXT.has(path.extname(p).toLowerCase())) analyze(p);
  }
}
if(!fs.existsSync(ROOT)) { console.error('Target directory not found:',ROOT); process.exit(2); }
filesUnder(ROOT);
const report={tool:'JSX-Ray Pro',version:'2.0.0',generatedAt:new Date().toISOString(),
  target:ROOT,method:'Acorn AST parsing with heuristic local data-flow checks',
  limitations:['Not a full interprocedural taint engine','No proof of exploitability','Review findings manually'],
  summary:{files: new Set(findings.map(x=>x.file)).size,findings:findings.length,sourceMaps:sourceMaps.length},
  findings,sourceMaps};
fs.mkdirSync(path.dirname(OUT),{recursive:true}); fs.writeFileSync(OUT,JSON.stringify(report,null,2));
console.log(`Analyzed ${report.summary.files} file(s); ${findings.length} finding(s).`);
console.log(`JSON report: ${OUT}`);
