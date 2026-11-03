"""Every scanner's report is read by scripts/report_readers.py (the same code the pipeline uses)."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import report_readers as rr  # noqa: E402

NEW = ROOT / "sample-scans" / "new-tools"


def read(name):
    return rr.read_report(name, (NEW / name).read_bytes())


@pytest.mark.parametrize("file, tool, category", [
    ("bandit.json", "bandit", "SAST"),
    ("bearer.json", "bearer", "SAST"),
    ("codeql.sarif.json", "codeql", "SAST"),
    ("osv-scanner.json", "osv-scanner", "SCA"),
    ("grype.json", "grype", "SCA"),
    ("dependency-check.json", "dependency-check", "SCA"),
    ("dependency-track.json", "dependency-track", "SCA"),
    ("nuclei.json", "nuclei", "DAST"),
    ("wapiti.json", "wapiti", "DAST"),
    ("nikto.json", "nikto", "DAST"),
    ("dastardly.xml", "dastardly", "DAST"),
    ("hadolint.json", "hadolint", "IAC"),
    ("kics.json", "kics", "IAC"),
    ("kubescape.sarif.json", "kubescape", "IAC"),
    ("conftest.json", "conftest", "IAC"),
])
def test_each_new_tool_is_read(file, tool, category):
    found = read(file)
    assert list(found) == [tool]
    assert found[tool], f"no findings read from {file}"
    for f in found[tool]:
        assert f["rule_id"] and f["title"]
        assert f["severity"] in ("critical", "high", "medium", "low", "info")
        assert rr.category(tool, f) == category


def test_twenty_tools_five_per_category():
    assert len(rr.CATEGORY) == 20
    for cat in ("SAST", "SCA", "DAST", "IAC"):
        assert sum(c == cat for c in rr.CATEGORY.values()) == 5, cat


def test_details_are_kept():
    codeql = read("codeql.sarif.json")["codeql"][0]
    assert (codeql["severity"], codeql["cwe"], codeql["file"], codeql["line"]) == ("high", "CWE-89", "routes/search.ts", 23)
    osv = read("osv-scanner.json")["osv-scanner"]
    assert len(osv) == 1  # GHSA + PYSEC ids for the same problem count once
    assert (osv[0]["rule_id"], osv[0]["severity"], osv[0]["file"]) == ("CVE-2020-1747", "critical", "requirements.txt :: pyyaml")
    grype = read("grype.json")["grype"][0]
    assert grype["rule_id"] == "CVE-2023-30861"  # same id as the other SCA tools
    dt = read("dependency-track.json")["dependency-track"][0]
    assert (dt["severity"], dt["cwe"]) == ("medium", "CWE-601")
    wapiti = read("wapiti.json")["wapiti"]
    assert {(w["title"], w["severity"]) for w in wapiti} == {("Cross Site Scripting", "medium"), ("Internal Server Error", "low")}
    assert wapiti[0]["cwe"] == "CWE-79"


def test_leaked_secrets_are_skipped():
    assert all(f["rule_id"] != "gitleaks" for f in read("bearer.json")["bearer"])
    assert all("Secret" not in f["title"] for f in read("kics.json")["kics"])


def test_kics_paths_are_relative_to_the_project():
    assert all(not f["file"].startswith(("../", "/path")) for f in read("kics.json")["kics"])


def test_dastardly_reads_issues_only():
    found = read("dastardly.xml")["dastardly"]
    assert [(f["title"], f["severity"], f["file"]) for f in found] == [
        ("Cross-site scripting (reflected)", "high", "/rest/products/search"),
        ("Content security policy: not enforced", "low", "/")]
    assert found[0]["cwe"] == "CWE-79"


def test_other_xml_is_ignored():
    zap = ROOT / "sample-scans" / "zap-results-first-scan.xml"
    assert rr.read_report(zap.name, zap.read_bytes()) == {}


def test_dastardly_survives_odd_characters_and_doctype_in_text():
    xml = (b'<?xml version="1.0"?><testsuites name="Dastardly scan results"><testsuite name="x">'
           b'<testcase name="Info leak"><failure message="Info leak found at http://h/p" type="Low">'
           b'<![CDATA[Severity: Low\nPath: /p\nbody: <!DOCTYPE html>]]> &#0; bad</failure></testcase>'
           b'</testsuite></testsuites>')
    found = rr.read_report("dastardly.xml", xml)["dastardly"]
    assert [(f["title"], f["severity"], f["file"]) for f in found] == [("Info leak", "low", "/p")]


def test_codeql_rules_in_query_packs_are_used():
    doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL", "rules": []}, "extensions": [
        {"name": "codeql/javascript-queries", "rules": [{"id": "js/xss", "shortDescription": {"text": "XSS"},
                                                         "properties": {"security-severity": "6.1",
                                                                        "tags": ["external/cwe/cwe-079"]}}]}]},
        "results": [{"ruleId": "js/xss", "message": {"text": "m"}, "locations": []}]}]}
    f = rr.read_sarif(doc)["codeql"][0]
    assert (f["title"], f["severity"], f["cwe"]) == ("XSS", "medium", "CWE-79")
