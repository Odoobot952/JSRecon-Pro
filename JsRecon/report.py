import json, os, html
def write_reports(result, prefix):
    os.makedirs(os.path.dirname(os.path.abspath(prefix)), exist_ok=True)
    jp, hp = prefix+".json", prefix+".html"
    with open(jp, "w", encoding="utf-8") as f: json.dump(result, f, indent=2, ensure_ascii=False)
    rows = "".join("<tr>" + "".join("<td>"+html.escape(str(item.get(k,"")))+"</td>" for k in
        ("request","status","content_type","response_bytes_read","elapsed_seconds")) + "</tr>" for item in result["checks"])
    errors = "".join("<li>"+html.escape(str(e))+"</li>" for e in result["errors"]) or "<li>None recorded</li>"
    target = result["target"]
    doc = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>JSRecon-Pro Report</title><style>body{{font:16px system-ui;max-width:1000px;margin:24px auto;padding:0 14px}}table{{border-collapse:collapse;width:100%;overflow-wrap:anywhere}}td,th{{border-bottom:1px solid #ccc;padding:7px;text-align:left}}th{{background:#eee}}.box{{padding:12px;background:#f6f6f6;border-radius:8px}}</style></head><body><h1>JSRecon-Pro Advanced Report</h1><p>Generated: {html.escape(result["generated_at"])}</p><p>Target: <code>{html.escape(target["scheme"])}://{html.escape(target["hostname"])}{html.escape(target["path"])}</code></p><div class="box"><b>Requests:</b> {result["summary"]["requests_sent"]} &nbsp; <b>Network errors:</b> {result["summary"]["network_errors"]} &nbsp; <b>Duration:</b> {result["summary"]["duration_seconds"]} s</div><h2>Checks</h2><table><thead><tr><th>#</th><th>Status</th><th>Content type</th><th>Bytes read</th><th>Seconds</th></tr></thead><tbody>{rows}</tbody></table><h2>Errors</h2><ul>{errors}</ul><h2>Notes</h2><ul>{''.join('<li>'+html.escape(n)+'</li>' for n in result['notes'])}</ul></body></html>'''
    with open(hp, "w", encoding="utf-8") as f: f.write(doc)
    return jp, hp
