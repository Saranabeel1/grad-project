import { api, fmtDateTime } from '../api'
import { Empty, ErrorBox, Loading, StatusBadge } from '../components/ui'
import { go } from '../nav'
import { useData } from '../useData'

// Pipeline Status (Figma): all runs with the Security Gate rule on top.
export default function RunsPage({ repo, title = 'Pipeline Status' }: { repo?: string; title?: string }) {
  const options = useData(() => api.dashboard(), [])
  const runs = useData(() => api.runs({ repo, limit: 200 }), [repo])

  return (
    <>
      <div className="page-head">
        <div>
          <h1>{title}</h1>
          <p className="sub">{runs.data ? `Latest ${runs.data.length} runs` : ' '}</p>
        </div>
        <select className="picker" value={repo ?? ''} onChange={(e) => go('runs', { repo: e.target.value })} aria-label="Project">
          <option value="">All projects</option>
          {options.data?.projects.map((p) => <option key={p}>{p}</option>)}
        </select>
      </div>
      <div className="banner">
        <strong>Security Gate rule:</strong>
        <span className="pink">Critical / High</span> → pipeline stops ·
        <span className="yellow">Medium / Low</span> → warning, pipeline continues
      </div>
      {runs.error && <ErrorBox message={runs.error} />}
      <div className="panel table-wrap">
        {!runs.data ? <Loading /> : runs.data.length === 0 ? (
          <Empty>No pipeline runs recorded.</Empty>
        ) : (
          <table className="table plain roomy">
            <thead>
              <tr><th>Run</th><th>Project</th><th>Branch</th><th>Commit</th><th>Result</th><th>Started</th><th /></tr>
            </thead>
            <tbody>
              {runs.data.map((r) => (
                <tr key={r.id}>
                  <td className="strong mono-num">#{r.run_id}</td>
                  <td>{r.repo}</td>
                  <td>{r.branch}</td>
                  <td className="mono">{r.commit_sha.slice(0, 7)}</td>
                  <td><StatusBadge status={r.status} /></td>
                  <td className="nowrap">{fmtDateTime(r.started_at)}</td>
                  <td>{r.run_url && <a className="link" href={r.run_url} target="_blank" rel="noreferrer">GitHub ↗</a>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  )
}
