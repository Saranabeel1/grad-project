import { SEVERITIES, type Dashboard } from './api'

export function toolName(tool: string): string {
  const names: Record<string, string> = {
    semgrep: 'Semgrep', sonarqube: 'SonarQube', codeql: 'CodeQL', bearer: 'Bearer', bandit: 'Bandit',
    trivy: 'Trivy', 'osv-scanner': 'OSV-Scanner', grype: 'Grype', 'dependency-check': 'Dependency-Check',
    'dependency-track': 'Dependency-Track', zap: 'ZAP', nuclei: 'Nuclei', wapiti: 'Wapiti', nikto: 'Nikto', dastardly: 'Dastardly',
    checkov: 'Checkov', kics: 'KICS', kubescape: 'Kubescape', conftest: 'Conftest', hadolint: 'Hadolint',
  }
  return names[tool] ?? tool
}

// Total findings reported per day; with more than two weeks of data, one point per week.
export function trendPoints(trend: Dashboard['trend']) {
  const daily = trend.map((t) => ({ date: t.date, total: SEVERITIES.reduce((n, s) => n + t[s], 0) }))
  if (daily.length <= 14) return daily
  const weekly = []
  for (let i = daily.length - 1; i >= 0; i -= 7) weekly.unshift(daily[i])
  return weekly
}
