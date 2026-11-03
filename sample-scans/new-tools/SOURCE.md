# Sample reports for the 15 new tools

Used by `backend/tests/test_readers.py` to check that `scripts/report_readers.py` reads every tool.

**Real output** (trimmed to a few entries). We ran these tools on 3 November 2026:
- `bandit.json`: Bandit 1.9 on `sample-target/`
- `bearer.json`: Bearer 2.1 on OWASP Juice Shop. We added one `gitleaks` entry to check that it gets skipped.
- `kics.json`: KICS on OWASP Juice Shop. We added one "Secret Management" entry to check that it gets skipped.
- `nikto.json`, `nuclei.json`: Nikto and Nuclei on a running Juice Shop
- `hadolint.json`: Hadolint 2.15 on Juice Shop and Online Boutique Dockerfiles
- `conftest.json`: Conftest with our `policy/` rules on GoogleCloudPlatform/microservices-demo

**Written by hand** from each tool's documented report format. We could not reach their vulnerability databases from the machine where we tested, so these files were not produced by the tools themselves:
- `osv-scanner.json`, `grype.json`, `dependency-check.json`, `dependency-track.json`, `wapiti.json`, `codeql.sarif.json`, `kubescape.sarif.json`, `dastardly.xml`

The first real run of `daily-scan.yml` on GitHub replaces the hand-written examples with real results.
