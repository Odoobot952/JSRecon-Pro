import time, ssl, urllib.request, urllib.error, uuid
from urllib.parse import urlsplit
from datetime import datetime, timezone

MAX_REQUESTS, MAX_RPS, MAX_TIMEOUT = 100, 2.0, 15.0
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def scan_url(url, allow_host, max_requests=10, rps=1.0, timeout=8.0, allow_http=False):
    u = urlsplit(url)
    schemes = ("https", "http") if allow_http else ("https",)
    if u.scheme not in schemes or not u.hostname:
        raise ValueError("Use a valid HTTPS URL (HTTP only with --allow-http for an isolated lab)")
    if u.username or u.password:
        raise ValueError("Credentials in URLs are not allowed")
    if u.hostname.lower().rstrip(".") != allow_host.lower().rstrip("."):
        raise ValueError("URL hostname must exactly match --allow-host")
    if not 1 <= max_requests <= MAX_REQUESTS:
        raise ValueError(f"--max-requests must be 1..{MAX_REQUESTS}")
    if not 0.1 <= rps <= MAX_RPS:
        raise ValueError(f"--rps must be 0.1..{MAX_RPS}")
    if not 1 <= timeout <= MAX_TIMEOUT:
        raise ValueError(f"--timeout must be 1..{MAX_TIMEOUT}")
    opener = urllib.request.build_opener(NoRedirect())
    checks, errors, start = [], [], time.monotonic()
    for i in range(max_requests):
        before = time.monotonic()
        req = urllib.request.Request(url, headers={
            "User-Agent": "JSRecon-Pro-Authorized-Staging-Checker/3.0",
            "X-JSRecon-Test": "JSReconMarker-" + uuid.uuid4().hex[:12],
            "Accept": "text/html,application/javascript;q=0.9,*/*;q=0.1"
        })
        status, ctype, size, redirect = None, "", 0, False
        try:
            with opener.open(req, timeout=timeout) as response:
                status, ctype = response.status, response.headers.get("Content-Type", "")
                size = len(response.read(262144))
        except urllib.error.HTTPError as e:
            status, ctype = e.code, e.headers.get("Content-Type", "")
            redirect = status in (301,302,303,307,308)
            if redirect: errors.append({"request": i+1, "kind": "redirect_blocked", "detail": "Redirect not followed"})
            try: size = len(e.read(262144))
            except Exception: pass
        except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError) as e:
            errors.append({"request": i+1, "kind": "network_error", "detail": str(e)[:250]})
        checks.append({"request": i+1, "status": status, "content_type": ctype,
                       "response_bytes_read": size, "redirect_blocked": redirect,
                       "elapsed_seconds": round(time.monotonic()-before, 3)})
        if i+1 < max_requests:
            time.sleep(max(0, (1.0/rps) - (time.monotonic()-before)))
    return {"tool":"JSRecon-Pro Advanced", "version":"3.0.0",
        "generated_at":datetime.now(timezone.utc).isoformat(),
        "target":{"scheme":u.scheme,"hostname":u.hostname,"path":u.path or "/"},
        "safety":{"exact_host_allowlist":allow_host,"max_requests":max_requests,
                  "rps_cap":MAX_RPS,"redirects_followed":False,"body_read_cap_bytes":262144},
        "summary":{"requests_sent":len(checks),"network_errors":len(errors),
                   "duration_seconds":round(time.monotonic()-start,3)},
        "checks":checks,"errors":errors,
        "notes":["Bounded benign GET smoke checks only; no exploit payloads are sent.",
                 "The marker is sent in a custom header and may be ignored by the application.",
                 "HTTP status and response size do not prove or disprove a vulnerability."]}
