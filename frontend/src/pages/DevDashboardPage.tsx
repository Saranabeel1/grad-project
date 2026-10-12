import { useState } from 'react'
import { api, fmtDateTime, location } from '../api'
import { SeverityDonut, ToolTypeBars, TrendDirection, TrendLine } from '../components/charts'
import { Avatar, Empty, ErrorBox, Loading, Panel, SeverityBadge, StatCard, StatusBadge } from '../components/ui'
import { go, href } from '../nav'
import { useData } from '../useData'

// Developer dashboard (Figma "Project A"): one project, with what is assigned to you on top.
// The design's AI suggestion tiles are left out until the AI part exists.
export default function DevDashboardPage({ repo, projects }: { repo: string; projects: string[] }) {
  const [mine, setMine] = useState(true)
  const dash = useData(() => api.dashboard(repo), [repo])
  const team = useData(() => api.team(repo), [repo])
  const assigned = useData(() => api.findings({ repo, assignee: 'me', status: 'open', limit: 5 }), [repo])
  const top = useData(() => api.findings({ repo, status: 'open', limit: 5 }), [repo])
  const runs = useData(() => api.runs({ repo, limit: 4 }), [repo])

  if (dash.error) return <ErrorBox message={dash.error} />
  const d = dash.data
  if (!d) return <Loading />

  const members = team.data?.members ?? []
  const fixes = mine ? assigned.data?.data : top.data?.data
  const warning = d.insights.find((i) => i.level !== 'good')
  const urgentMine = assigned.data?.data.filter((f) => f.severity === 'critical' || f.severity === 'high').length ?? 0

  return (
    <>
      <div className="page-head">
        <div className="title-row">
          <h1>{repo}</h1>
          {members.length > 0 && (
            <span className="members">
              <span className="avatar-stack">{members.slice(0, 5).map((m) => <Avatar key={m.id} name={m.name} />)}</span>
              {members.length} {members.length === 1 ? 'member' : 'members'}
            </span>
          )}
        </div>
        {projects.length > 1 && (
          <label className="switch">
            Project
            <select value={repo} onChange={(e) => go('dashboard', { repo: e.target.value })}>
              {projects.map((p) => <option key={p}>{p}</option>)}
            </select>
          </label>
        )}
      </div>

      <div className="stats">
        <StatCard icon="shield" tone="red" label="Open findings" value={d.open_findings.toLocaleString()} delta={d.new_last_7d}
          note={`${assigned.data?.total ?? 0} assigned to you`} />
        <StatCard icon="person" label="Assigned to you" value={assigned.data?.total ?? '–'}
          note={urgentMine ? `${urgentMine} critical or high` : 'open findings to fix'} />
        <StatCard icon="branch" label="Pipeline pass rate" value={d.pass_rate ?? '–'} unit={d.pass_rate === null ? '' : '%'}
          ring={d.pass_rate} note={d.runs_total ? `${d.runs_passed} of ${d.runs_total} runs passed` : 'no runs recorded'} />
        <StatCard icon="clock" label="Mean time to fix" value={d.mean_days_to_fix ?? '–'}
          unit={d.mean_days_to_fix === null ? '' : 'days'} note="from detection to fixed" />
      </div>

      <div className="grid overview-charts">
        <Panel title="Open findings by severity"><SeverityDonut counts={d.by_severity} /></Panel>
        <Panel title="Findings over time" action={<TrendDirection trend={d.trend} />}>
          {d.trend.length > 1 ? <TrendLine trend={d.trend} /> : <Empty>Needs scans on at least two days.</Empty>}
        </Panel>
        <Panel title="Findings by tool type"><ToolTypeBars byTool={d.by_tool} /></Panel>
      </div>

      <div className="grid dev-bottom">
        <Panel
          title={<span className="title-row">Priority fixes
            <span className="toggle">
              <button className={mine ? 'on' : ''} onClick={() => setMine(true)}>Mine</button>
              <button className={mine ? '' : 'on'} onClick={() => setMine(false)}>All team</button>
            </span></span>}
          action={<a className="link" href={href('findings', { repo, assignee: mine ? 'me' : undefined, status: 'open' })}>View all findings →</a>}
        >
          {!fixes ? <Loading /> : fixes.length === 0 ? (
            <Empty>{mine ? 'Nothing is assigned to you. Pick a finding from "All team".' : 'No open findings.'}</Empty>
          ) : (
            <ul className="rows">
              {fixes.map((f) => (
                <li key={f.id}>
                  <SeverityBadge severity={f.severity} />
                  <div className="grow">
                    <div className="title">{f.title}</div>
                    <div className="muted mono ellipsis">{location(f) || f.rule_id}</div>
                  </div>
                  {f.assignee_name ? <Avatar name={f.assignee_name} /> : <span className="muted small hide-sm">Unassigned</span>}
                  <a className="pill-button" href={href('finding', { id: String(f.id) })}>View</a>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="Recent runs" action={<a className="link" href={href('runs', { repo })}>View all runs →</a>}>
          {runs.data?.length ? (
            <ul className="rows">
              {runs.data.map((r) => (
                <li key={r.id}>
                  <span className="strong mono-num">#{r.run_id.slice(-4)}</span>
                  <div className="grow">
                    <div>{r.branch}</div>
                    <div className="muted small mono">{r.commit_sha.slice(0, 7)}</div>
                  </div>
                  <StatusBadge status={r.status} />
                  <span className="muted small nowrap">{fmtDateTime(r.started_at)}</span>
                </li>
              ))}
            </ul>
          ) : <Empty>No pipeline runs recorded.</Empty>}
        </Panel>
      </div>

      {warning && (
        <section className="panel dark">
          <div className="eyebrow">Risk warning</div>
          <h2 className="warning-title">{warning.title}</h2>
          <p className="warning-text">{warning.detail} Suggested: {warning.action}.</p>
          <a className="link light" href={href('insights', { repo })}>All warnings for this project →</a>
        </section>
      )}
    </>
  )
}
