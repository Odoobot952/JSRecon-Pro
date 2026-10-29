# JSRecon-Pro Advanced for Termux

Python-only, resource-bounded starter. Generates a large corpus locally, but never sends that corpus to a website. The network checker performs only benign, bounded GET smoke checks against an exact allow-listed HTTPS hostname.

## Termux setup
```sh
pkg update
pkg install python
```
Unzip this project, then from its directory:

```sh
python -m jsrecon_pro.cli corpus --count 1000000 --out out/corpus.jsonl
python -m jsrecon_pro.cli scan-url https://staging.example.test/ --allow-host staging.example.test --max-requests 10 --rps 1 --out out/report
```
Replace the example hostname with the exact staging host you are authorized to test.

Reports: `out/report.json` and `out/report.html`.

Controls: corpus count capped at 5,000,000; streaming JSONL output; network request budget capped at 100; rate capped at 2 requests/second; timeout capped at 15 seconds; exact hostname allowlist; redirects not followed; each response body read capped at 256 KiB; HTTPS required unless `--allow-http` is used for an isolated lab. No crawling, form submission, exploit execution, or uncontrolled fuzzing.

The generated corpus is for local analysis and test-case management. Do not send millions of cases to a live service. Use only during an authorized staging test window.
1. Install dependencies on Kali Linux or Parrot OS
sudo apt update
sudo apt install -y python3 unzip


2. Extract the project
If the ZIP is in your Downloads folder:
cd ~/Downloads
unzip jsrecon_pro_advanced_termux.zip
cd jsrecon_pro_advanced


If you already extracted it, navigate directly to the project directory.
3. Run JSRecon-Pro
Generate one million local test cases:
python3 -m jsrecon_pro.cli corpus \
  --count 1000000 \
  --out out/corpus.jsonl


Run a bounded check against an authorized staging site, replacing the example hostname with your own:
python3 -m jsrecon_pro.cli scan-url https://staging.example.test/ \
  --allow-host staging.example.test \
  --max-requests 10 \
  --rps 1 \
  --out out/report


View the HTML report:
xdg-open out/report.html


Read the JSON report in the terminal:
python3 -m json.tool out/report.json | less


4. Test the installation
python3 -m unittest discover -s tests -v
