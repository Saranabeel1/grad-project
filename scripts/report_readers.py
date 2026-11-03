"""Readers for scanner reports (20 tools; SARIF or each tool's own JSON).

SAST: Semgrep, SonarQube, CodeQL, Bearer, Bandit
SCA:  Trivy, OSV-Scanner, Grype, OWASP Dependency-Check, OWASP Dependency-Track
DAST: ZAP, Nuclei, Wapiti, Nikto, Dastardly (Burp)
IaC:  Checkov, KICS, Kubescape, Conftest, Hadolint (and Trivy's misconfiguration checks)

Shared by fetch_live.py, fetch_daily.py and push_reports.py, so every route reads reports the same way.
Holds no project names, so it is safe to keep in a public repository.
"""
import json
import re
import xml.etree.ElementTree as ET

CATEGORY = {
    "semgrep": "SAST", "sonarqube": "SAST", "codeql": "SAST", "bearer": "SAST", "bandit": "SAST",
    "trivy": "SCA", "osv-scanner": "SCA", "grype": "SCA", "dependency-check": "SCA", "dependency-track": "SCA",
    "zap": "DAST", "nuclei": "DAST", "wapiti": "DAST", "nikto": "DAST", "dastardly": "DAST",
    "checkov": "IAC", "kics": "IAC", "kubescape": "IAC", "conftest": "IAC", "hadolint": "IAC",
}
TOOL_NAMES = {"semgrep": "semgrep", "opengrep": "semgrep", "trivy": "trivy", "checkov": "checkov",
              "zap": "zap", "owasp zap": "zap", "sonarqube": "sonarqube", "sonar": "sonarqube",
              "codeql": "codeql", "bearer": "bearer", "bandit": "bandit", "osv-scanner": "osv-scanner",
              "grype": "grype", "dependency-check": "dependency-check", "dependency-track": "dependency-track",
              "nuclei": "nuclei", "wapiti": "wapiti", "nikto": "nikto", "kics": "kics",
              "kubescape": "kubescape", "conftest": "conftest", "hadolint": "hadolint", "dastardly": "dastardly"}
SEV = {"critical": "critical", "high": "high", "error": "high", "medium": "medium", "moderate": "medium",
       "warning": "medium", "low": "low", "note": "low", "info": "info", "none": "info", "unknown": "info", "negligible": "info"}


# ------------------------------------------------------------------ reading report files
def finding(rule, title, severity, cwe=None, file=None, line=None, description=None):
    return {"rule_id": str(rule)[:300], "title": str(title or rule)[:300], "severity": severity,
            "cwe": cwe, "file": str(file)[:500] if file else None, "line": int(line) if line else None,
            "description": (description or "")[:1000] or None}


def first_cwe(text):
    """The first CWE number in any text or list, written as CWE-79 (tools write cwe-079, CWE-79 or just 79)."""
    m = re.search(r"cwe-(\d+)", json.dumps(text), re.I) if text else None
    return f"CWE-{int(m.group(1))}" if m else None


def cwe_number(n):
    """CWE from a bare number such as "79" or 79."""
    return f"CWE-{int(n)}" if str(n or "").strip().isdigit() else None


def cvss_level(score):
    """Severity from a 0-10 CVSS score."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low" if s > 0 else "info"


def tool_of(name):
    name = (name or "").lower()
    return next((t for k, t in TOOL_NAMES.items() if k in name), None)


def read_sarif(doc):
    """SARIF: the shared report format. Returns {tool: [findings]}."""
    out = {}
    for run in doc.get("runs", []):
        tool = tool_of(run.get("tool", {}).get("driver", {}).get("name"))
        if not tool:
            continue  # a tool we do not read
        rules = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            rid = res.get("ruleId", "unknown")
            rule = rules.get(rid, {})
            if is_secret(tool, rid, rule):
                continue
            props = {**rule.get("properties", {}), **res.get("properties", {})}
            level = cvss_level(props.get("security-severity"))  # GitHub's 0-10 score
            if not level:
                level = SEV.get(str(res.get("level") or rule.get("defaultConfiguration", {}).get("level")
                                    or "warning").lower(), "medium")
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            title = (rule.get("shortDescription") or {}).get("text") or (res.get("message") or {}).get("text")
            out.setdefault(tool, []).append(finding(
                rid, title, level, first_cwe(props.get("tags") or props.get("cwe")),
                loc.get("artifactLocation", {}).get("uri"), loc.get("region", {}).get("startLine"),
                (res.get("message") or {}).get("text")))
    return out


def is_secret(tool, rid, rule):
    text = f"{rid} {json.dumps(rule.get('properties', {}))}".lower()
    return (tool == "checkov" and "ckv_secret" in text) or (tool == "trivy" and "secret" in text)


def read_semgrep_json(doc):
    return {"semgrep": [finding(r.get("check_id"), r.get("extra", {}).get("message", "").split("\n")[0],
                                SEV.get(str(r.get("extra", {}).get("severity", "")).lower(), "medium"),
                                first_cwe(r.get("extra", {}).get("metadata", {}).get("cwe")),
                                r.get("path"), r.get("start", {}).get("line"), r.get("extra", {}).get("message"))
                        for r in doc.get("results", []) if isinstance(r, dict) and r.get("check_id")]}


def read_trivy_json(doc):
    out = []
    for res in doc.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            out.append(finding(v.get("VulnerabilityID"), f"{v.get('VulnerabilityID')} in {v.get('PkgName')}",
                               SEV.get(str(v.get("Severity")).lower(), "info"), first_cwe(v.get("CweIDs")),
                               f"{res.get('Target')} :: {v.get('PkgName')}", None,
                               f"Installed {v.get('InstalledVersion')}, fixed in {v.get('FixedVersion') or 'none'}."))
        for m in res.get("Misconfigurations") or []:
            if m.get("Status", "FAIL") == "FAIL":
                out.append(finding(m.get("ID"), m.get("Title"), SEV.get(str(m.get("Severity")).lower(), "info"),
                                   None, res.get("Target"), (m.get("CauseMetadata") or {}).get("StartLine"),
                                   m.get("Message")))
        # res["Secrets"] is skipped on purpose
    return {"trivy": out}


def read_checkov_json(doc):
    out = []
    for part in doc if isinstance(doc, list) else [doc]:
        for c in part.get("results", {}).get("failed_checks", []):
            if str(c.get("check_id", "")).startswith("CKV_SECRET"):
                continue
            out.append(finding(c.get("check_id"), c.get("check_name"),
                               SEV.get(str(c.get("severity") or "medium").lower(), "medium"), None,
                               str(c.get("file_path", "")).lstrip("/"), (c.get("file_line_range") or [None])[0],
                               f"Failed for resource {c.get('resource')}"))
    return {"checkov": out}


ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}


def read_zap_json(doc):
    out = []
    for site in doc.get("site", []):
        for a in site.get("alerts", []):
            uri = ((a.get("instances") or [{}])[0].get("uri") or site.get("@name") or "").split("?")[0]
            cwe = a.get("cweid")
            out.append(finding(f"zap-{a.get('pluginid')}", a.get("alert") or a.get("name"),
                               ZAP_RISK.get(str(a.get("riskcode")), "info"),
                               f"CWE-{cwe}" if cwe and str(cwe) not in ("-1", "0") else None, uri, None,
                               f"{a.get('alert')} found on {a.get('count') or len(a.get('instances') or [])} URL(s)."))
    return {"zap": out}


# SonarQube's own levels. "impacts" is the newer way (BLOCKER/HIGH/MEDIUM/LOW/INFO); "severity" the older one.
SONAR_IMPACT = {"blocker": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}
SONAR_OLD = {"blocker": "critical", "critical": "high", "major": "medium", "minor": "low", "info": "info"}


def read_sonarqube_json(doc):
    """The file export_sonarqube.py saves: SonarQube's security issues and hotspots."""
    out, rules = [], doc.get("rules") or {}
    for i in doc.get("issues") or []:
        if str(i.get("rule")).startswith("secrets:"):
            continue  # leaked keys and passwords are skipped, as for the other tools
        security = [x["severity"] for x in i.get("impacts") or [] if x.get("softwareQuality") == "SECURITY"]
        level = (SONAR_IMPACT.get(security[0].lower()) if security else None) \
            or SONAR_OLD.get(str(i.get("severity")).lower(), "medium")
        out.append(finding(i.get("rule"), rules.get(i.get("rule")) or i.get("message"), level,
                           first_cwe(i.get("tags")), str(i.get("component", "")).split(":", 1)[-1],
                           i.get("line"), i.get("message")))
    for h in doc.get("hotspots") or []:
        out.append(finding(h.get("ruleKey"), h.get("message"),
                           SONAR_IMPACT.get(str(h.get("vulnerabilityProbability")).lower(), "medium"), None,
                           str(h.get("component", "")).split(":", 1)[-1], h.get("line"),
                           f"Security hotspot ({h.get('securityCategory')}): needs a person to check it."))
    return {"sonarqube": out}


# ------------------------------------------------------------------ SAST
def read_bandit_json(doc):
    """bandit -f json"""
    return {"bandit": [finding(r.get("test_id"), r.get("issue_text") or r.get("test_name"),
                               SEV.get(str(r.get("issue_severity")).lower(), "medium"),
                               cwe_number((r.get("issue_cwe") or {}).get("id")),
                               r.get("filename"), r.get("line_number"), r.get("issue_text"))
                       for r in doc.get("results") or []]}


BEARER_LEVELS = ("critical", "high", "medium", "low", "warning")


def read_bearer_json(doc):
    """bearer scan --format json: {"critical": [...], "high": [...], ...}"""
    out = []
    for level in BEARER_LEVELS:
        for r in doc.get(level) or []:
            if "gitleaks" in str(r.get("id")):
                continue  # Bearer's built-in leaked-key detector: skipped, as for the other tools
            out.append(finding(r.get("id"), r.get("title"), SEV.get(level, "medium"),
                               cwe_number((r.get("cwe_ids") or [None])[0]), r.get("filename"),
                               r.get("line_number"), r.get("title")))
    return {"bearer": out}


# ------------------------------------------------------------------ SCA
def read_osv_json(doc):
    """osv-scanner --format json. One finding per group of aliases (the same problem under CVE/GHSA/PYSEC ids)."""
    out = []
    for res in doc.get("results") or []:
        source = (res.get("source") or {}).get("path", "")
        for p in res.get("packages") or []:
            pkg = p.get("package") or {}
            vulns = {v.get("id"): v for v in p.get("vulnerabilities") or []}
            groups = p.get("groups") or [{"ids": [i]} for i in vulns]
            for g in groups:
                ids = g.get("ids") or []
                aliases = set(ids) | {a for i in ids for a in (vulns.get(i) or {}).get("aliases") or []}
                rid = next((a for a in sorted(aliases) if a.startswith("CVE-")), None) or (ids or ["?"])[0]
                v = next((vulns[i] for i in ids if i in vulns), {})
                level = cvss_level(g.get("max_severity")) or SEV.get(
                    str((v.get("database_specific") or {}).get("severity")).lower(), "medium")
                out.append(finding(rid, f"{rid} in {pkg.get('name')}", level,
                                   first_cwe((v.get("database_specific") or {}).get("cwe_ids")),
                                   f"{source.rsplit('/target/', 1)[-1]} :: {pkg.get('name')}", None,
                                   f"{v.get('summary') or ''} Installed {pkg.get('version')}.".strip()))
    return {"osv-scanner": out}


def read_grype_json(doc):
    """grype -o json"""
    out = []
    for m in doc.get("matches") or []:
        v, a = m.get("vulnerability") or {}, m.get("artifact") or {}
        rid = v.get("id")
        cve = next((r.get("id") for r in m.get("relatedVulnerabilities") or [] if str(r.get("id")).startswith("CVE-")), None)
        if cve and not str(rid).startswith("CVE-"):
            rid = cve  # same id as the other SCA tools where there is one
        where = ((a.get("locations") or [{}])[0].get("path") or "").lstrip("/")
        fixes = (v.get("fix") or {}).get("versions") or []
        out.append(finding(rid, f"{rid} in {a.get('name')}", SEV.get(str(v.get("severity")).lower(), "info"),
                           first_cwe(v.get("cwes")), f"{where} :: {a.get('name')}", None,
                           f"Installed {a.get('version')}, fixed in {', '.join(fixes) or 'none'}."))
    return {"grype": out}


def read_dependency_check_json(doc):
    """OWASP Dependency-Check: dependency-check --format JSON"""
    out = []
    for d in doc.get("dependencies") or []:
        name = (d.get("packages") or [{}])[0].get("id") or d.get("fileName")
        for v in d.get("vulnerabilities") or []:
            score = (v.get("cvssv3") or {}).get("baseScore") or (v.get("cvssv2") or {}).get("score")
            level = SEV.get(str(v.get("severity")).lower()) or cvss_level(score) or "medium"
            out.append(finding(v.get("name"), f"{v.get('name')} in {d.get('fileName')}", level,
                               first_cwe(v.get("cwes")), f"{d.get('filePath', '').split('/target/', 1)[-1]} :: {name}",
                               None, v.get("description")))
    return {"dependency-check": out}


def read_dependency_track_json(doc):
    """The file export_dependency_track.py saves: Dependency-Track's findings for one project."""
    out = []
    for f in doc.get("findings") or []:
        c, v = f.get("component") or {}, f.get("vulnerability") or {}
        rid = v.get("vulnId")
        out.append(finding(rid, f"{rid} in {c.get('name')}", SEV.get(str(v.get("severity")).lower(), "info"),
                           cwe_number(v.get("cweId")) or first_cwe(v.get("cwes")),
                           f"{c.get('purl') or c.get('name')}", None,
                           f"{v.get('title') or ''} Installed {c.get('version')}.".strip()))
    return {"dependency-track": out}


# ------------------------------------------------------------------ DAST
def read_nuclei_json(doc):
    """nuclei -json-export (a list)"""
    out = []
    for r in doc:
        info = r.get("info") or {}
        out.append(finding(r.get("template-id"), info.get("name"), SEV.get(str(info.get("severity")).lower(), "info"),
                           first_cwe((info.get("classification") or {}).get("cwe-id")),
                           str(r.get("matched-at") or r.get("url") or "").split("?")[0], None,
                           (info.get("description") or "").strip() or None))
    return {"nuclei": out}


WAPITI_LEVEL = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}


def read_wapiti_json(doc):
    """wapiti -f json. "vulnerabilities" are real findings; "anomalies" (server errors, timeouts) count as low."""
    out = []
    for part, default in (("vulnerabilities", "medium"), ("anomalies", "low")):
        for name, items in (doc.get(part) or {}).items():
            cwe = first_cwe(((doc.get("classifications") or {}).get(name) or {}).get("ref"))
            for v in items or []:
                level = WAPITI_LEVEL.get(v.get("level"), default) if part == "vulnerabilities" else default
                where = f"{v.get('method', 'GET')} {v.get('path', '')}"
                out.append(finding(f"wapiti-{v.get('module') or name}".lower().replace(" ", "-"), name, level, cwe,
                                   where + (f" ({v['parameter']})" if v.get("parameter") else ""), None, v.get("info")))
    return {"wapiti": out}


def read_nikto_json(doc):
    """nikto -Format json: a list of hosts (older versions: one host)."""
    out = []
    for host in doc if isinstance(doc, list) else [doc]:
        for v in host.get("vulnerabilities") or []:
            out.append(finding(f"nikto-{v.get('id')}", v.get("msg"), "low", None,
                               f"{v.get('method', 'GET')} {v.get('url', '')}".split("?")[0], None, v.get("msg")))
    return {"nikto": out}


# ------------------------------------------------------------------ IaC
def read_kics_json(doc):
    """kics scan --report-formats json (results.json)"""
    out = []
    for q in doc.get("queries") or []:
        if q.get("category") == "Secret Management":
            continue  # passwords and keys in config files are skipped, as for the other tools
        for f in q.get("files") or []:
            path = re.sub(r"^(\.\./)*(path|src|work|target)/", "", str(f.get("file_name", "")))
            out.append(finding(q.get("query_id"), q.get("query_name"),
                               SEV.get(str(q.get("severity")).lower(), "medium"), cwe_number(q.get("cwe")),
                               path, f.get("line"), f.get("actual_value")))
    return {"kics": out}


def read_conftest_json(doc):
    """conftest test -o json: [{filename, namespace, failures: [{msg, metadata}], warnings: [...]}]"""
    out = []
    for r in doc:
        for part, default in (("failures", "high"), ("warnings", "medium")):
            for f in r.get(part) or []:
                meta = f.get("metadata") or {}
                out.append(finding(meta.get("id") or f"{r.get('namespace')}-{f.get('msg')}", meta.get("title") or f.get("msg"),
                                   SEV.get(str(meta.get("severity")).lower(), default), cwe_number(meta.get("cwe")),
                                   str(r.get("filename", "")).split("/target/", 1)[-1].removeprefix("target/").removeprefix("./"),
                                   None, f.get("msg")))
    return {"conftest": out}


def read_dastardly_xml(data):
    """Dastardly (Burp Suite's free CI scanner) writes a JUnit XML report: one <failure> per issue."""
    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        return {}  # never expand XML entities from a file
    out = []
    for case in ET.fromstring(data).iter("testcase"):
        fail = case.find("failure")
        if fail is None:
            continue  # a check that passed
        text = fail.text or ""
        sev = re.search(r"Severity:\s*(\w+)", text)
        path = re.search(r"Path:\s*(\S+)", text)
        name = case.get("name") or fail.get("message") or "issue"
        issue = name.split(" found at ")[0].strip()
        where = path.group(1) if path else name.split(" found at ")[-1]
        out.append(finding(f"dastardly-{re.sub(r'[^a-z0-9]+', '-', issue.lower()).strip('-')}", issue,
                           SEV.get(str(fail.get("type") or (sev.group(1) if sev else "")).lower(), "medium"),
                           first_cwe(text), where.split("?")[0], None, text.strip()[:1000] or None))
    return {"dastardly": out}


HADOLINT_LEVEL = {"error": "high", "warning": "medium", "info": "low", "style": "info"}


def read_hadolint_json(doc):
    """hadolint -f json: [{code, level, file, line, message}]. DL = Hadolint's rules, SC = ShellCheck's."""
    return {"hadolint": [finding(r.get("code"), r.get("message"), HADOLINT_LEVEL.get(r.get("level"), "low"), None,
                                 re.sub(r"^(\./|target/)", "", str(r.get("file", ""))), r.get("line"), r.get("message"))
                         for r in doc]}


def read_report(name, data):
    """Work out what kind of report a file is from its contents, then read it."""
    if data.lstrip().startswith(b"<"):
        if b"<testsuite" in data and ("dastardly" in str(name).lower() or b"Dastardly" in data):
            return read_dastardly_xml(data)
        return {}  # other XML (for example ZAP's) is read elsewhere
    try:
        doc = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    if isinstance(doc, dict) and "runs" in doc and "version" in doc:
        return read_sarif(doc)  # CodeQL, Kubescape (and any tool above that wrote SARIF)
    if isinstance(doc, list):
        first = next((x for x in doc if isinstance(x, dict)), {})
        if "template-id" in first:
            return read_nuclei_json(doc)
        if "code" in first and "level" in first and "file" in first:
            return read_hadolint_json(doc)
        if "namespace" in first and "filename" in first:
            return read_conftest_json(doc)
        if "vulnerabilities" in first and "host" in first:
            return read_nikto_json(doc)
    if isinstance(doc, dict):
        if "kics_version" in doc:
            return read_kics_json(doc)
        if "matches" in doc and "descriptor" in doc:
            return read_grype_json(doc)
        if "reportSchema" in doc and "dependencies" in doc:
            return read_dependency_check_json(doc)
        if doc.get("dependency-track") and "findings" in doc:
            return read_dependency_track_json(doc)
        if "classifications" in doc and isinstance(doc.get("vulnerabilities"), dict):
            return read_wapiti_json(doc)
        if "generated_at" in doc and "metrics" in doc and isinstance(doc.get("results"), list):
            return read_bandit_json(doc)
        if isinstance(doc.get("results"), list) and ("experimental_config" in doc or any(
                isinstance(r, dict) and "packages" in r for r in doc["results"])):
            return read_osv_json(doc)
        if doc and set(doc) <= set(BEARER_LEVELS) and all(isinstance(v, list) for v in doc.values()):
            return read_bearer_json(doc)
        if "host" in doc and isinstance(doc.get("vulnerabilities"), list):
            return read_nikto_json(doc)
    if isinstance(doc, dict) and "sonarqube" in doc and "issues" in doc:
        return read_sonarqube_json(doc)
    if isinstance(doc, dict) and "Results" in doc and "SchemaVersion" in doc:
        return read_trivy_json(doc)
    if isinstance(doc, dict) and "site" in doc and "@version" in doc:
        return read_zap_json(doc)
    if isinstance(doc, dict) and isinstance(doc.get("results"), list) and "errors" in doc:
        return read_semgrep_json(doc)
    if (isinstance(doc, list) and doc and "check_type" in doc[0]) or (isinstance(doc, dict) and "check_type" in doc):
        return read_checkov_json(doc)
    return {}


def category(tool, f):
    if tool == "trivy" and not f["rule_id"].startswith(("CVE-", "GHSA-")):
        return "IAC"  # Trivy misconfiguration checks are IaC findings
    return CATEGORY[tool]
