import { api } from '../api'
import { InsightCard } from '../components/insights'
import { Empty, ErrorBox, Loading, Meter } from '../components/ui'
import { go } from '../nav'
import { useData } from '../useData'

export default function InsightsPage({ repo }: { repo?: string }) {
  const { data: d, error } = useData(() => api.dashboard(repo), [repo])
  if (error) return <ErrorBox message={error} />
  if (!d) return <Loading />
  const max = Math.max(...d.repeated_types.map((t) => t.count), 1)

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Risk Insights</h1>
          <p className="sub">Predictive warnings across {repo ?? 'all projects'}</p>
        </div>
        <select className="picker" value={repo ?? ''} onChange={(e) => go('insights', { repo: e.target.value })} aria-label="Project">
          <option value="">All projects</option>
          {d.projects.map((p) => <option key={p}>{p}</option>)}
        </select>
      </div>
      <div className="banner">
        <span className="banner-tag">Rule-based · no AI</span>
        A warning appears when the same vulnerability type is open in 2 or more projects or 3 or more times in one project,
        or when a project's last 3 runs failed.
      </div>
      <div className="grid insights-grid">
        <div className="insight-list">
          {d.insights.length ? d.insights.map((i) => <InsightCard key={i.title} insight={i} />) : (
            <div className="panel"><Empty>No warnings right now.</Empty></div>
          )}
        </div>
        <section className="panel">
          <header className="panel-head stacked">
            <h2>Most repeated types</h2>
            <span className="muted small">{repo ?? 'All projects'} · open findings</span>
          </header>
          <ul className="meters wide-label">
            {d.repeated_types.map((t) => (
              <li key={t.type}>
                <span className="meter-label" title={t.type}>{t.type}</span>
                <Meter value={t.count} max={max} color="var(--navy)" />
                <b>{t.count}</b>
              </li>
            ))}
          </ul>
          <p className="note-box">A type is the CWE when the scanner gives one, otherwise the scanner's rule. Info findings are left out.</p>
        </section>
      </div>
    </>
  )
}
