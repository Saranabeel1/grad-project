import { useEffect, useState } from 'react'
import { go, href } from '../nav'
import { SEVERITIES, api, fmtDate, location } from '../api'
import { toolName } from '../labels'
import { Avatar, Empty, ErrorBox, SeverityBadge, StatusBadge } from '../components/ui'
import { SEVERITY_LABEL } from '../severity'
import { useData } from '../useData'

const PAGE_SIZE = 50
const CATEGORIES = ['SAST', 'SCA', 'IAC', 'DAST', 'SECRETS']

export default function FindingsPage({ params }: { params: Record<string, string> }) {
  const { repo, tool, severity, status, tool_type, assignee, q = '' } = params
  const page = Number(params.page ?? 1)
  const [search, setSearch] = useState(q)

  // Wait until typing stops before searching.
  useEffect(() => {
    if (search === q) return
    const t = setTimeout(() => go('findings', { ...params, q: search, page: undefined }), 350)
    return () => clearTimeout(t)
  }, [search]) // eslint-disable-line react-hooks/exhaustive-deps

  const options = useData(() => api.dashboard(), [])
  const list = useData(
    () => api.findings({ repo, tool, severity, status, tool_type, assignee, q, limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE }),
    [repo, tool, severity, status, tool_type, assignee, q, page],
  )
  const team = useData(() => (repo ? api.team(repo) : Promise.resolve(null)), [repo])

  const set = (key: string, value: string) => go('findings', { ...params, [key]: value, page: undefined })
  const total = list.data?.total ?? 0
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const tools = options.data?.by_tool.map((t) => t.tool).sort() ?? []

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Findings</h1>
          <p className="sub">{list.data ? `${total.toLocaleString()} findings match` : ' '}</p>
        </div>
      </div>

      <div className="filters panel">
        <label>
          Project
          <select value={repo ?? ''} onChange={(e) => set('repo', e.target.value)}>
            <option value="">All projects</option>
            {options.data?.projects.map((p) => <option key={p}>{p}</option>)}
          </select>
        </label>
        <label className="grow">
          Search
          <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Title, rule, file or CWE" />
        </label>
        <label>
          Tool
          <select value={tool ?? ''} onChange={(e) => set('tool', e.target.value)}>
            <option value="">All tools</option>
            {tools.map((t) => <option key={t} value={t}>{toolName(t)}</option>)}
          </select>
        </label>
        <label>
          Category
          <select value={tool_type ?? ''} onChange={(e) => set('tool_type', e.target.value)}>
            <option value="">All categories</option>
            {CATEGORIES.map((c) => <option key={c}>{c}</option>)}
          </select>
        </label>
        <label>
          Severity
          <select value={severity ?? ''} onChange={(e) => set('severity', e.target.value)}>
            <option value="">All severities</option>
            {SEVERITIES.map((s) => <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>)}
          </select>
        </label>
        <label>
          Status
          <select value={status ?? ''} onChange={(e) => set('status', e.target.value)}>
            <option value="">All statuses</option>
            <option value="open">Open</option>
            <option value="fixed">Fixed</option>
            <option value="ignored">Ignored</option>
          </select>
        </label>
        <label>
          Assigned
          <select value={assignee ?? ''} onChange={(e) => set('assignee', e.target.value)}>
            <option value="">All team</option>
            <option value="me">Me</option>
            <option value="none">Nobody yet</option>
            {team.data?.members.filter((m) => !m.you).map((m) => <option key={m.id} value={m.id}>{m.name}</option>)}
          </select>
        </label>
      </div>

      {list.error && <ErrorBox message={list.error} />}
      <div className="panel table-wrap">
        {list.data && list.data.data.length === 0 ? (
          <Empty>No findings match these filters.</Empty>
        ) : (
          <table className="table plain">
            <thead>
              <tr>
                <th>Severity</th><th>Finding</th>{!repo && <th>Project</th>}<th>Tool</th>
                <th className="hide-sm">Detected</th><th>Status</th><th>Assigned</th>
              </tr>
            </thead>
            <tbody>
              {list.data?.data.map((f) => (
                <tr key={f.id} className="clickable" onClick={() => (window.location.hash = href('finding', { id: String(f.id) }).slice(1))}>
                  <td><SeverityBadge severity={f.severity} /></td>
                  <td className="finding-cell">
                    <a className="title plain-link" href={href('finding', { id: String(f.id) })}>{f.title}</a>
                    <div className="muted mono ellipsis">{location(f) || f.rule_id}</div>
                  </td>
                  {!repo && <td>{f.repo}</td>}
                  <td className="nowrap">{toolName(f.tool)} <span className="muted">· {f.tool_type}</span></td>
                  <td className="nowrap hide-sm">{fmtDate(f.first_seen)}</td>
                  <td><StatusBadge status={f.status} /></td>
                  <td className="nowrap">{f.assignee_name ? <><Avatar name={f.assignee_name} /> {f.assignee_name}</> : <span className="muted">–</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {list.loading && <p className="loading">Loading…</p>}
      </div>

      {pages > 1 && (
        <div className="pager">
          <button disabled={page <= 1} onClick={() => go('findings', { ...params, page: String(page - 1) })}>← Previous</button>
          <span>Page {page} of {pages}</span>
          <button disabled={page >= pages} onClick={() => go('findings', { ...params, page: String(page + 1) })}>Next →</button>
        </div>
      )}
    </>
  )
}
