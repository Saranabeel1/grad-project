"""Readers for scanner reports (Semgrep, Trivy, Checkov, ZAP, SonarQube; SARIF or JSON).

Shared by fetch_live.py, fetch_daily.py and push_reports.py, so every route reads reports the same way.
Holds no project names, so it is safe to keep in a public repository.
"""
import json
import re

CATEGORY = {"semgrep": "SAST", "trivy": "SCA", "zap": "DAST", "checkov": "IAC", "sonarqube": "SAST"}
TOOL_NAMES = {"semgrep": "semgrep", "opengrep": "semgrep", "trivy": "trivy", "checkov": "checkov",
              "zap": "zap", "owasp zap": "zap", "sonarqube": "sonarqube", "sonar": "sonarqube"}
SEV = {"critical": "critical", "high": "high", "error": "high", "medium": "medium", "moderate": "medium",
       "warning": "medium", "low": "low", "note": "low", "info": "info", "none": "info", "unknown": "info"}


# ------------------------------------------------------------------ reading report files
def finding(rule, title, severity, cwe=None, file=None, line=None, description=None):
    return {"rule_id": str(rule)[:300], "title": str(title or rule)[:300], "severity": severity,
            "cwe": cwe, "file": str(file)[:500] if file else None, "line": int(line) if line else None,
            "description": (description or "")[:1000] or None}


def first_cwe(text):
    m = re.search(r"CWE-\d+", json.dumps(text)) if text else None
    return m.group(0) if m else None


def tool_of(name):
    name = (name or "").lower()
    return next((t for k, t in TOOL_NAMES.items() if k in name), None)


def read_sarif(doc):
    """SARIF: the shared report format. Returns {tool: [findings]}."""
    out = {}
    for run in doc.get("runs", []):
        tool = tool_of(run.get("tool", {}).get("driver", {}).get("name"))
        if not tool:
            continue  # not one of our four tools (CodeQL, Bandit, ...)
        rules = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            rid = res.get("ruleId", "unknown")
            rule = rules.get(rid, {})
            if is_secret(tool, rid, rule):
                continue
            props = {**rule.get("properties", {}), **res.get("properties", {})}
            sev = str(props.get("security-severity") or "")
            if sev.replace(".", "").isdigit():  # GitHub's 0-10 score
                s = float(sev)
                level = "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"
            else:
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


def read_report(name, data):
    """Work out what kind of report a file is from its contents, then read it."""
    try:
        doc = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    if isinstance(doc, dict) and "runs" in doc and "version" in doc:
        return read_sarif(doc)
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
