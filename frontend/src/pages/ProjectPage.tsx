import { api, fmtDate, fmtDateTime, location } from '../api'
import { SeverityMeters, TrendDirection, TrendLine } from '../components/charts'
import { toolName } from '../labels'
import { Empty, ErrorBox, Loading, Panel, SeverityBadge, StatCard, StatusBadge } from '../components/ui'
import { go, href } from '../nav'
import { useData } from '../useData'

// One project, read-only (Figma "Project A · View only").
export default function ProjectPage({ repo }: { repo?: string }) {
  const dash = useData(() => api.dashboard(repo), [repo])
  const findings = useData(() => api.findings({ repo, status: 'open', limit: 8 }), [repo])
  const runs = useData(() => api.runs({ repo, limit: 6 }), [repo])

  if (!repo) {
    go('projects')
    return null
  }
  if (dash.error) return <ErrorBox message={dash.error} />
  const d = dash.data
  if (!d) return <Loading />

  return (
    <>
      <a className="back" href={href('projects')}>← Projects</a>
      <div className="page-head">
        <div>
          <h1>{repo} <span className="tag">View only</span></h1>
          <p className="sub">Scanned by {d.by_tool.map((t) => toolName(t.tool)).join(', ') || 'no tools yet'}</p>
        </div>
        <label className="switch">
          Switch project
          <select value={repo} onChange={(e) => go('project', { repo: e.target.value })}>
            {d.projects.map((p) => <option key={p}>{p}</option>)}
          </select>
        </label>
      </div>

      <div className="stats">
        <StatCard label="Open findings" value={d.open_findings.toLocaleString()} delta={d.new_last_7d} />
        <StatCard label="No longer reported" value={<span className="green">{d.resolved.toLocaleString()}</span>} />
        <StatCard label="Pipeline pass rate" value={d.pass_rate ?? '–'} unit={d.pass_rate === null ? '' : '%'}
          note={d.runs_total ? `${d.runs_passed} of ${d.runs_total} runs passed` : 'no runs recorded'} />
        <StatCard label="Mean time to fix" value={d.mean_days_to_fix ?? '–'} unit={d.mean_days_to_fix === null ? '' : 'days'} />
      </div>

      <div className="grid project-charts">
        <Panel title="Open by severity">
          <SeverityMeters counts={d.by_severity} />
        </Panel>
        <Panel title="Findings over time" action={<TrendDirection trend={d.trend} />}>
          {d.trend.length > 1 ? <TrendLine trend={d.trend} /> : <Empty>Needs scans on at least two days.</Empty>}
        </Panel>
      </div>

      <div className="grid project-bottom">
        <Panel title="Findings" action={<a className="link" href={href('findings', { repo })}>All findings →</a>}>
          {findings.data?.data.length ? (
            <table className="table plain">
              <thead><tr><th>Severity</th><th>Finding</th><th>Tool</th><th>Last seen</th></tr></thead>
              <tbody>
                {findings.data.data.map((f) => (
                  <tr key={f.id}>
                    <td><SeverityBadge severity={f.severity} /></td>
                    <td className="finding-cell">
                      <div className="title">{f.title}</div>
                      <div className="muted mono ellipsis">{location(f) || f.rule_id}</div>
                    </td>
                    <td className="nowrap">{toolName(f.tool)} <span className="muted">· {f.tool_type}</span></td>
                    <td className="nowrap muted">{fmtDate(f.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <Empty>No open findings.</Empty>}
        </Panel>
        <Panel title="Recent runs" action={<a className="link" href={href('runs', { repo })}>All runs →</a>}>
          {runs.data?.length ? (
            <ul className="rows">
              {runs.data.map((r) => (
                <li key={r.id}>
                  <span className="strong mono small">#{r.run_id}</span>
                  <div className="grow">
                    <div>{r.branch}</div>
                    <div className="muted small">{fmtDateTime(r.started_at)} · <span className="mono">{r.commit_sha.slice(0, 7)}</span></div>
                  </div>
                  <StatusBadge status={r.status} />
                </li>
              ))}
            </ul>
          ) : <Empty>No pipeline runs recorded.</Empty>}
        </Panel>
      </div>
    </>
  )
}
