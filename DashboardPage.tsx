import { api, fmtDate } from '../api'
import { SeverityDonut, ToolTypeBars, TrendDirection, TrendLine } from '../components/charts'
import { toolName } from '../labels'
import { Empty, ErrorBox, Loading, Meter, Panel, StatCard, StatusBadge } from '../components/ui'
import { href } from '../nav'
import { useData } from '../useData'

// Manager overview: all projects (Figma "Overview").
export default function DashboardPage() {
  const { data: d, error } = useData(() => api.dashboard(), [])
  if (error) return <ErrorBox message={error} />
  if (!d) return <Loading />

  const warnings = d.insights.filter((i) => i.level !== 'good')
  const highWarnings = warnings.filter((i) => i.level === 'high').length
  const maxOpen = Math.max(...d.compare.map((c) => c.open), 1)
  const first = d.trend[0]?.date
  const last = d.trend[d.trend.length - 1]?.date

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Overview</h1>
          <p className="sub">All projects{first ? ` · ${fmtDate(first)} to ${fmtDate(last)}` : ''}</p>
        </div>
      </div>

      {d.found_total === 0 && d.runs_total === 0 ? (
        <Empty>No data yet. Results appear after the next scan (see the README).</Empty>
      ) : (
        <>
          <div className="stats">
            <StatCard icon="shield" tone="red" label="Open findings" value={d.open_findings.toLocaleString()} delta={d.new_last_7d}
              note={`${d.still_reported.toLocaleString()} still in the latest scans · ${d.resolved.toLocaleString()} no longer reported`} />
            <StatCard icon="branch" label="Pipeline success rate" value={d.pass_rate ?? '–'} unit={d.pass_rate === null ? '' : '%'}
              ring={d.pass_rate} note={d.runs_total ? `${d.runs_passed} of ${d.runs_total} runs passed` : 'no runs recorded'} />
            <StatCard icon="clock" label="Mean time to fix" value={d.mean_days_to_fix ?? '–'}
              unit={d.mean_days_to_fix === null ? '' : 'days'} note="from detection to no longer reported" />
            <StatCard icon="warning" label="Risk warnings" value={warnings.length} note={`${highWarnings} high`} />
          </div>

          <div className="grid overview-charts">
            <Panel title="Open findings by severity">
              <SeverityDonut counts={d.by_severity} />
            </Panel>
            <Panel title="Findings over time" action={<TrendDirection trend={d.trend} />}>
              {d.trend.length > 1 ? <TrendLine trend={d.trend} /> : <Empty>Needs scans on at least two days.</Empty>}
            </Panel>
            <Panel title="Findings by tool type">
              <ToolTypeBars byTool={d.by_tool} />
            </Panel>
          </div>

          <div className="grid overview-bottom">
            <Panel title="Projects compared" action={<a className="link" href={href('projects')}>Open a project →</a>}>
              <div className="table-scroll"><table className="table plain">
                <thead>
                  <tr><th>Project</th><th className="hide-sm">Scanners</th><th>Open findings</th><th /><th>Last run</th></tr>
                </thead>
                <tbody>
                  {d.compare.map((c) => (
                    <tr key={c.repo} className="clickable" onClick={() => (window.location.hash = href('project', { repo: c.repo }).slice(1))}>
                      <td className="strong nowrap">{c.repo}</td>
                      <td className="muted small hide-sm">{c.tools.map(toolName).join(', ')}</td>
                      <td className="bar-cell"><Meter value={c.open} max={maxOpen} color="var(--navy)" /></td>
                      <td className="strong num">{c.open.toLocaleString()}</td>
                      <td>{c.last_run ? <StatusBadge status={c.last_run} /> : <span className="muted">–</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table></div>
            </Panel>

            <section className="panel dark">
              <header className="panel-head">
                <h2>Risk Insights</h2>
                <span className="small">{highWarnings} high warnings</span>
              </header>
              {warnings.length ? (
                warnings.slice(0, 2).map((w) => (
                  <div className="dark-card" key={w.title}>
                    <strong>{w.title}</strong>
                    <span>{w.detail}</span>
                  </div>
                ))
              ) : (
                <div className="dark-card"><span>No warnings right now.</span></div>
              )}
              <a className="button green" href={href('insights')}>View all insights</a>
            </section>
          </div>
        </>
      )}
    </>
  )
}

