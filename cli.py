import argparse, sys
from .scanner import scan_local, scan_url
from .report import write_reports

def main():
    p=argparse.ArgumentParser(prog="jsrecon",description="Authorized JavaScript security triage.")
    sub=p.add_subparsers(dest="cmd",required=True)
    l=sub.add_parser("scan-dir",help="Analyze local source")
    l.add_argument("path")
    l.add_argument("--out",default="report")
    u=sub.add_parser("scan-url",help="Passively analyze same-origin assets from an authorized URL")
    u.add_argument("url")
    u.add_argument("--allow-host",action="append",required=True,help="Authorized hostname; repeat for additional hosts")
    u.add_argument("--max-assets",type=int,default=60)
    u.add_argument("--timeout",type=int,default=10)
    u.add_argument("--out",default="report")
    args=p.parse_args()
    try:
        if args.cmd=="scan-dir":
            report=scan_local(args.path)
        else:
            if not 1 <= args.max_assets <= 200: raise ValueError("--max-assets must be between 1 and 200")
            if not 2 <= args.timeout <= 60: raise ValueError("--timeout must be between 2 and 60 seconds")
            report=scan_url(args.url,args.allow_host,args.max_assets,args.timeout)
        j,h=write_reports(report,args.out)
        print(f"Scanned assets/files: {report['assets_scanned']}")
        print(f"Findings: {report['finding_count']}")
        print(f"JSON report: {j.resolve()}")
        print(f"HTML report: {h.resolve()}")
        if report["errors"]: print(f"Warnings/errors: {len(report['errors'])} (see HTML/JSON report)")
    except (ValueError,OSError) as e:
        print(f"error: {e}",file=sys.stderr); raise SystemExit(2)

if __name__=="__main__": main()
