import { SEVERITIES, api } from '../api'
import { toolName } from '../labels'
import { Avatar, Empty, ErrorBox, Loading, SeverityBadge, StatusBadge } from '../components/ui'
import { go } from '../nav'
import { useData } from '../useData'

export default function ProjectsPage() {
  const { data: d, error } = useData(() => api.dashboard(), [])
  if (error) return <ErrorBox message={error} />
  if (!d) return <Loading />

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Projects</h1>
          <p className="sub">{d.projects.length} projects · scanned by {d.by_tool.length} tools</p>
        </div>
      </div>
      <div className="panel table-wrap">
        {d.compare.length === 0 ? (
          <Empty>No projects yet.</Empty>
        ) : (
          <table className="table plain roomy">
            <thead>
              <tr><th>Project</th><th>Scanners</th><th>Open</th><th>By severity</th><th>Pass rate</th><th>Last run</th><th /></tr>
            </thead>
            <tbody>
              {d.compare.map((c) => (
                <tr key={c.repo} className="clickable" onClick={() => go('project', { repo: c.repo })}>
                  <td className="nowrap"><Avatar name={c.repo} /> <span className="strong project-link">{c.repo} →</span></td>
                  <td className="muted">{c.tools.map(toolName).join(', ') || '–'}</td>
                  <td className="big-num">{c.open.toLocaleString()}</td>
                  <td>
                    <div className="chips">
                      {SEVERITIES.filter((s) => s !== 'info' && c[s] > 0).map((s) => <SeverityBadge key={s} severity={s} count={c[s]} />)}
                    </div>
                  </td>
                  <td>{c.pass_rate === null ? <span className="muted">–</span> : `${c.pass_rate}%`}</td>
                  <td>{c.last_run ? <StatusBadge status={c.last_run} /> : <span className="muted">–</span>}</td>
                  <td className="chevron">›</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  )
}
