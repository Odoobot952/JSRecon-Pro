import argparse, sys
from .corpus import write_corpus
from .scanner import scan_url
from .report import write_reports

def main():
    p = argparse.ArgumentParser(prog="jsrecon-pro")
    s = p.add_subparsers(dest="cmd", required=True)
    c = s.add_parser("corpus")
    c.add_argument("--count", type=int, default=1000)
    c.add_argument("--out", required=True)
    n = s.add_parser("scan-url")
    n.add_argument("url")
    n.add_argument("--allow-host", required=True)
    n.add_argument("--max-requests", type=int, default=10)
    n.add_argument("--rps", type=float, default=1.0)
    n.add_argument("--timeout", type=float, default=8.0)
    n.add_argument("--allow-http", action="store_true")
    n.add_argument("--out", required=True)
    a = p.parse_args()
    try:
        if a.cmd == "corpus":
            print(f"Wrote {write_corpus(a.count, a.out)} local cases to {a.out}")
        else:
            result = scan_url(a.url, a.allow_host, a.max_requests, a.rps, a.timeout, a.allow_http)
            jp, hp = write_reports(result, a.out)
            print(f"JSON report: {jp}\nHTML report: {hp}\nRequests sent: {result['summary']['requests_sent']}")
    except (ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        raise SystemExit(2)
if __name__ == "__main__":
    main()
