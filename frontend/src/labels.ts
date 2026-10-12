import { SEVERITIES, type Dashboard } from './api'

export function toolName(tool: string): string {
  const names: Record<string, string> = { semgrep: 'Semgrep', trivy: 'Trivy', checkov: 'Checkov', zap: 'ZAP', sonarqube: 'SonarQube' }
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
