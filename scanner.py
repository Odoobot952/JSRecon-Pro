import hashlib, html, json, os, re, subprocess, urllib.error, urllib.parse, urllib.request
from pathlib import Path
from .rules import SKIP_DIRS, EXTENSIONS

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
MAX_FILE_BYTES = 2_000_000
MAX_HTML_BYTES = 2_000_000
USER_AGENT = "JSRecon-Pro/2.0 (authorized-security-assessment)"

def redact(s):
    s = re.sub(r"""(?i)((?:api[_-]?key|client[_-]?secret|access[_-]?token|private[_-]?key)\s*[:=]\s*['"])[^'"]{4,}(['"])""", r"\1[REDACTED]\2", s)
    return s[:240]

def fingerprint(path, rule_id, line, evidence):
    return hashlib.sha256(f"{path}|{rule_id}|{line}|{evidence}".encode()).hexdigest()[:16]

def ast_analyze(source):
    worker = Path(__file__).with_name("ast_worker.js")
    try:
        p = subprocess.run(["node", str(worker)], input=json.dumps({"source": source}), text=True,
                          capture_output=True, timeout=12, check=False)
        if p.returncode != 0:
            return [], f"Node AST worker failed: {p.stderr[:200]}"
        result = json.loads(p.stdout)
        return result.get("findings", []), result.get("parseError")
    except FileNotFoundError:
        return [], "Node.js not found; install Node.js 18+ and run npm install."
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return [], f"AST analysis error: {exc}"

def regex_findings(source):
    patterns = [
      ("JSCRED001","Possible hard-coded credential","high","low",
       re.compile(r"""(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|private[_-]?key|aws_secret_access_key)\b\s*[:=]\s*(['"])[^'"]{8,}\1"""),
       "Credential-like string assignment; may be a public identifier or test value.",
       "Verify privileges. Revoke/rotate confirmed secrets and keep privileged credentials server-side."),
      ("JSMAP001","Source map reference present","info","high",
       re.compile(r"sourceMappingURL\s*=\s*([^\s*]+)", re.I),
       "A source map reference may expose original source when deployed publicly.",
       "Review release policy and whether source maps should be public."),
      ("JSSTOR001","Sensitive-looking browser storage key","medium","low",
       re.compile(r"""(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*(['"`])[^'"`]*(?:token|jwt|secret|session|auth)[^'"`]*\1""", re.I),
       "A storage key suggests authentication material may be browser-readable.",
       "Verify stored value and threat model; avoid long-lived credentials in script-readable storage."),
    ]
    findings=[]
    lines=source.splitlines()
    for rid,title,sev,conf,pat,desc,fix in patterns:
        for m in pat.finditer(source):
            line=source.count("\n",0,m.start())+1
            ev=redact(lines[line-1].strip() if line <= len(lines) else "")
            findings.append({"id":rid,"title":title,"severity":sev,"confidence":conf,"line":line,"column":1,
                "evidence":ev,"description":desc,"remediation":fix})
    return findings

def make_finding(f, path, source):
    line = max(1, int(f.get("line", 1)))
    lines = source.splitlines()
    ev = redact(f.get("evidence") or (lines[line-1] if line <= len(lines) else ""))
    return {**f, "file":path, "line":line, "evidence":ev,
            "validation_status":"needs_manual_validation",
            "fingerprint":fingerprint(path,f.get("id","UNKNOWN"),line,ev)}

def analyze_source(source, path):
    ast, parse_error = ast_analyze(source)
    raw = ast + regex_findings(source)
    # Deduplicate by rule and location; retain highest confidence.
    best={}
    for f in raw:
        item=make_finding(f,path,source)
        key=(item["id"],item["file"],item["line"])
        if key not in best or item.get("confidence")=="high":
            best[key]=item
    return list(best.values()), parse_error

def scan_local(root):
    root=Path(root).resolve()
    if not root.is_dir(): raise ValueError(f"Not a directory: {root}")
    findings=[]; assets=[]; errors=[]
    for cur,dirs,names in os.walk(root):
        dirs[:]=[d for d in dirs if d not in SKIP_DIRS]
        for name in names:
            p=Path(cur)/name
            if p.suffix.lower() not in EXTENSIONS: continue
            try:
                if p.stat().st_size > MAX_FILE_BYTES:
                    errors.append({"file":str(p.relative_to(root)),"error":"Skipped: file exceeds 2 MB cap"}); continue
                source=p.read_text(encoding="utf-8",errors="replace")
            except OSError as e:
                errors.append({"file":str(p.relative_to(root)),"error":str(e)}); continue
            rel=str(p.relative_to(root))
            assets.append({"url":None,"file":rel,"bytes":len(source.encode("utf-8")),"kind":"local"})
            fs,err=analyze_source(source,rel); findings.extend(fs)
            if err: errors.append({"file":rel,"error":err})
    return build_report("local",None,assets,findings,errors)

def allowed_host(host, allow_hosts):
    host=(host or "").lower().rstrip(".")
    for allowed in allow_hosts:
        allowed=allowed.lower().strip().rstrip(".")
        if host==allowed or host.endswith("."+allowed): return True
    return False

def safe_url(url, allow_hosts):
    p=urllib.parse.urlparse(url)
    if p.scheme not in ("https","http") or not p.hostname:
        raise ValueError("Only http:// and https:// URLs are supported.")
    if not allowed_host(p.hostname,allow_hosts):
        raise ValueError(f"Host {p.hostname!r} is not allowlisted. Add --allow-host {p.hostname} only if authorized.")
    if p.username or p.password: raise ValueError("Credentials in URLs are not supported.")
    return p

def fetch(url, allow_hosts, timeout=10, max_bytes=MAX_HTML_BYTES):
    safe_url(url,allow_hosts)
    req=urllib.request.Request(url,headers={"User-Agent":USER_AGENT,"Accept":"text/html,application/javascript,text/javascript,*/*;q=0.5"})
    opener=urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req,timeout=timeout) as resp:
            final=resp.geturl()
            safe_url(final,allow_hosts)
            data=resp.read(max_bytes+1)
            if len(data)>max_bytes: raise ValueError(f"Response exceeded {max_bytes} byte limit: {url}")
            charset=resp.headers.get_content_charset() or "utf-8"
            return data.decode(charset,errors="replace"), resp.headers.get("Content-Type",""), final, resp.status
    except urllib.error.HTTPError as e:
        raise ValueError(f"HTTP {e.code} fetching {url}") from e
    except urllib.error.URLError as e:
        raise ValueError(f"Network error fetching {url}: {e.reason}") from e

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "Redirect not followed; rerun against an explicitly authorized final URL", headers, fp)

def same_origin(a,b):
    x,y=urllib.parse.urlparse(a),urllib.parse.urlparse(b)
    return (x.scheme.lower(),x.hostname,(x.port or (443 if x.scheme=="https" else 80))) == \
           (y.scheme.lower(),y.hostname,(y.port or (443 if y.scheme=="https" else 80)))

def scan_url(start_url, allow_hosts, max_assets=60, timeout=10):
    p=safe_url(start_url,allow_hosts)
    if p.scheme!="https":
        # HTTP is allowed only when explicitly invoked, but highlight it in report.
        pass
    html_text,ctype,final,status=fetch(start_url,allow_hosts,timeout,MAX_HTML_BYTES)
    base=final
    assets=[{"url":final,"file":"(document)","bytes":len(html_text.encode()),"kind":"html","status":status}]
    findings=[]; errors=[]; visited=set()
    # Minimal passive HTML discovery. Only script src URLs and explicit source-map references are followed.
    script_srcs=re.findall(r"""<script\b[^>]*\bsrc\s*=\s*(['"])(.*?)\1""",html_text,re.I|re.S)
    # Basic HTML checks for password forms posting to HTTP.
    for m in re.finditer(r"<form\b[^>]*>",html_text,re.I):
        tag=m.group(0)
        if re.search(r"""action\s*=\s*(['"])http://""",tag,re.I) and re.search(r"""<input\b[^>]*type\s*=\s*(['"])password""",html_text[m.end():m.end()+4000],re.I):
            findings.append(make_finding({"id":"JSHTML001","title":"Password form may submit over HTTP","severity":"high","confidence":"medium",
                "line":html_text.count("\n",0,m.start())+1,"evidence":redact(tag),"description":"A password form appears to use an HTTP action.",
                "remediation":"Use HTTPS for credential submission and enforce HTTPS server-side."},"(document)",html_text))
    todo=[]
    for _,src in script_srcs:
        u=urllib.parse.urljoin(base,src.strip())
        if same_origin(base,u) and u not in visited: todo.append(u)
    # Inline scripts are analyzed as well.
    for idx,block in enumerate(re.findall(r"<script\b(?![^>]*\bsrc=)[^>]*>(.*?)</script\s*>",html_text,re.I|re.S),1):
        fs,err=analyze_source(block,f"(inline-script-{idx})")
        findings.extend(fs)
        if err: errors.append({"file":f"(inline-script-{idx})","error":err})
    while todo and len(visited)<max_assets:
        u=todo.pop(0)
        if u in visited: continue
        visited.add(u)
        try:
            text,ct,final_u,st=fetch(u,allow_hosts,timeout,MAX_FILE_BYTES)
            if not same_origin(base,final_u): raise ValueError("Cross-origin asset rejected.")
            assets.append({"url":final_u,"file":final_u,"bytes":len(text.encode()),"kind":"javascript","status":st,"content_type":ct})
            fs,err=analyze_source(text,final_u); findings.extend(fs)
            if err: errors.append({"file":final_u,"error":err})
            maps=re.findall(r"sourceMappingURL\s*=\s*([^\s*]+)",text)
            for mapref in maps[:2]:
                if mapref.startswith("data:"): continue
                mu=urllib.parse.urljoin(final_u,mapref.strip())
                if same_origin(base,mu) and mu not in visited and len(visited)+len(todo)<max_assets:
                    todo.append(mu)
        except Exception as e:
            errors.append({"file":u,"error":str(e)})
    if todo:
        errors.append({"file":"(discovery)","error":f"Asset cap reached ({max_assets}); remaining assets skipped."})
    # Source maps can contain original sources in sourcesContent. Analyze only same-origin maps already fetched.
    for a in list(assets):
        if not a.get("url") or not str(a["url"]).endswith(".map"): continue
        try:
            body,_,_,_=fetch(a["url"],allow_hosts,timeout,MAX_FILE_BYTES)
            data=json.loads(body)
            for i,src in enumerate(data.get("sourcesContent") or []):
                if isinstance(src,str):
                    label=f'{a["url"]}::{(data.get("sources") or ["source"])[i] if i<len(data.get("sources") or []) else "source"}'
                    fs,err=analyze_source(src,label); findings.extend(fs)
                    if err: errors.append({"file":label,"error":err})
        except Exception as e: errors.append({"file":a["url"],"error":f"Source-map parse/read failed: {e}"})
    return build_report("live_passive",final,assets,findings,errors)

def build_report(mode,target,assets,findings,errors):
    unique={}
    for f in findings:
        key=(f.get("id"),f.get("file"),f.get("line"))
        if key not in unique or f.get("confidence")=="high": unique[key]=f
    fs=sorted(unique.values(),key=lambda x:(SEV_ORDER.get(x.get("severity","info"),4),x.get("file",""),x.get("line",0),x.get("id","")))
    counts={s:sum(1 for f in fs if f.get("severity")==s) for s in SEV_ORDER}
    return {"tool":"JSRecon Pro","version":"2.0.0","mode":mode,"target":target,
      "assets_scanned":len(assets),"finding_count":len(fs),"severity_counts":counts,
      "assets":assets,"findings":fs,"errors":errors,
      "disclaimer":"Passive heuristic findings require manual validation; absence of findings does not prove security."}
