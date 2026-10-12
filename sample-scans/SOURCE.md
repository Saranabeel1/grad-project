# Sample scan files

Copied on 2026-10-09 from the DefectDojo project's test data:
https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans
(DefectDojo is BSD-3-Clause licensed; cite it in the report.)

| File | Scanner | Category | Findings |
|---|---|---|---|
| semgrep-many_vulns.json | Semgrep | SAST (code) | 48: 13 ERROR, 35 WARNING; 44 have a CWE |
| trivy-scheme_2_many_vulns.json | Trivy | SCA (libraries) | 5: 1 critical, 1 high, 3 medium |
| zap-results-first-scan.xml | OWASP ZAP | DAST (running website) | 15: 4 high, 3 medium, 4 low, 4 info |
| zap-results-second-scan.xml | OWASP ZAP | DAST | same site scanned again later, for a trend |
| checkov-report-severity.json | Checkov | IaC (Terraform) | 4: 1 high, 2 medium, 1 low |
