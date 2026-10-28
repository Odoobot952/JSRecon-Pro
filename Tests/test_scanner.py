import tempfile, unittest
from pathlib import Path
from jsrecon.scanner import analyze_source, allowed_host, safe_url

class ScannerTests(unittest.TestCase):
    def test_ast_finds_eval_and_html_sink(self):
        fs, err=analyze_source("eval(input); el.innerHTML = location.search;", "sample.js")
        ids={x["id"] for x in fs}
        self.assertIn("JSCODE001",ids)
        self.assertIn("JSXSS001",ids)
        self.assertFalse(err)

    def test_allowlist_subdomains(self):
        self.assertTrue(allowed_host("app.example.com",["example.com"]))
        self.assertFalse(allowed_host("example.com.attacker.invalid",["example.com"]))

    def test_rejects_unapproved_host(self):
        with self.assertRaises(ValueError): safe_url("https://example.org",["example.com"])

if __name__=="__main__": unittest.main()
