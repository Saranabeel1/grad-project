import { api, fmtDateTime } from '../api'
import { Avatar, Empty, ErrorBox, Loading, Panel, StatusBadge } from '../components/ui'
import { go, href } from '../nav'
import { useData } from '../useData'

// Team (Figma): the project's developers with their numbers, and what happened lately.
export default function TeamPage({ repo, projects }: { repo: string; projects: string[] }) {
  const { data: t, error } = useData(() => api.team(repo), [repo])
  if (error) return <ErrorBox message={error} />
  if (!t) return <Loading />

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Team</h1>
          <p className="sub">{repo} · {t.members.length} {t.members.length === 1 ? 'member' : 'members'}</p>
        </div>
        {projects.length > 1 && (
          <label className="switch">
            Project
            <select value={repo} onChange={(e) => go('team', { repo: e.target.value })}>
              {projects.map((p) => <option key={p}>{p}</option>)}
            </select>
          </label>
        )}
      </div>

      {t.members.length === 0 ? (
        <Empty>No developers are in this project yet. Add them with: python -m app.users add</Empty>
      ) : (
        <div className="team-cards">
          {t.members.map((m) => (
            <a key={m.id} className={`panel member${m.you ? ' you' : ''}`} href={href('findings', { repo, assignee: String(m.id), status: 'open' })}>
              <div className="member-head">
                <Avatar name={m.name} />
                <div>
                  <strong>{m.name}</strong>
                  <small className={m.you ? 'you-label' : ''}>Developer{m.you ? ' · You' : ''}</small>
                </div>
              </div>
              <div className="member-stats">
                <span><small>Open</small><b>{m.open}</b></span>
                <span><small>Fixed (30d)</small><b className="green">{m.fixed_30d}</b></span>
              </div>
              <small className="muted">Last active · {m.last_active ? fmtDateTime(m.last_active) : 'not yet'}</small>
            </a>
          ))}
        </div>
      )}

      <Panel title="Team activity">
        {t.activity.length === 0 ? <Empty>Nothing yet.</Empty> : (
          <ul className="rows">
            {t.activity.map((a, i) => (
              <li key={i}>
                {a.who ? <Avatar name={a.who} /> : <span className="avatar run-dot">⟳</span>}
                <div className="grow strong">
                  {a.finding_id ? <a className="plain-link" href={href('finding', { id: String(a.finding_id) })}>{a.who} {a.text}</a> : a.text}
                </div>
                {a.status && <StatusBadge status={a.status} />}
                <span className="muted small nowrap">{fmtDateTime(a.at)}</span>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </>
  )
}
