import { useState } from 'react'
import { api, fmtDate, fmtDateTime, location, type FindingDetail } from '../api'
import type { User } from '../auth'
import { toolName } from '../labels'
import { ErrorBox, Loading, Panel, SeverityBadge, StatusBadge } from '../components/ui'
import { href } from '../nav'
import { useData } from '../useData'

const STATUS_WORD: Record<string, string> = { fixed: 'Marked as fixed', ignored: 'Ignored', open: 'Reopened' }

// One finding (Figma "Finding detail"): what it is, how to fix it, who has it, and what happened so far.
// The steps follow the real flow: detected → assigned → marked fixed → verified by the next scan.
export default function FindingPage({ id, user }: { id?: string; user: User }) {
  const [version, setVersion] = useState(0)
  const [saving, setSaving] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const { data: f, error } = useData(() => api.finding(id ?? ''), [id, version])

  if (error) return <ErrorBox message={error} />
  if (!f) return <Loading />

  const change = async (c: { assignee_id?: number | null; status?: string }) => {
    setSaving(true)
    setActionError(null)
    try {
      await api.updateFinding(f.id, c)
      setVersion((v) => v + 1)
    } catch (e) {
      setActionError((e as Error).message)
    } finally {
      setSaving(false)
    }
  }

  const isMember = f.members.some((m) => m.id === user.id)
  const verified = f.status === 'fixed' && !f.still_reported
  const steps = [
    { done: true, title: 'Detected', note: `by ${toolName(f.tool)}` },
    { done: !!f.assignee_id, title: 'Assigned', note: f.assignee_name ? `to ${f.assignee_name}` : 'to a developer' },
    { done: f.status === 'fixed', title: 'Fixed', note: 'marked by the developer' },
    { done: verified, title: 'Verified', note: verified ? 'gone from the latest scan' : 'next pipeline run' },
  ]

  return (
    <>
      <a className="back" href={href('findings', { repo: f.repo })}>← Findings</a>
      <div className="page-head">
        <div>
          <h1>{f.title} <SeverityBadge severity={f.severity} /> <StatusBadge status={f.status} /></h1>
          <p className="sub">
            {f.repo} · Found by {f.tool_type} · {toolName(f.tool)}
            {f.file && ` · ${location(f)}`} · Detected {fmtDate(f.first_seen)}
            {f.assignee_name && ` · Assigned to ${f.assignee_name}`}
          </p>
        </div>
      </div>

      <ol className="steps panel">
        {steps.map((s, i) => (
          <li key={s.title} className={s.done ? 'done' : ''}>
            <span className="step-dot">{s.done ? '✓' : i + 1}</span>
            <span><strong>{s.title}</strong><small>{s.note}</small></span>
          </li>
        ))}
      </ol>

      <div className="grid finding-grid">
        <Panel title="The problem and how to fix it" action={<span className="tag">{f.type_name}</span>}>
          {f.description && <p className="pre problem">{f.description}</p>}
          <dl className="facts">
            <dt>Rule</dt><dd className="mono">{f.rule_id}</dd>
            {f.cwe && (<><dt>Weakness</dt><dd><a href={`https://cwe.mitre.org/data/definitions/${f.cwe.replace('CWE-', '')}.html`} target="_blank" rel="noreferrer">{f.cwe}</a></dd></>)}
            <dt>Where</dt><dd className="mono">{location(f) || 'not given by the scanner'}</dd>
          </dl>
          <div className="fix-box">
            <strong>How to fix</strong>
            <span>{capitalize(f.how_to_fix)}.</span>
          </div>
        </Panel>

        <Panel title="Who fixes it">
          <label className="field">
            Assigned to
            <select value={f.assignee_id ?? ''} disabled={saving}
              onChange={(e) => change({ assignee_id: e.target.value ? Number(e.target.value) : null })}>
              <option value="">Nobody yet</option>
              {f.members.map((m) => <option key={m.id} value={m.id}>{m.name}{m.id === user.id ? ' (you)' : ''}</option>)}
            </select>
          </label>
          {isMember && f.assignee_id !== user.id && (
            <button className="pill-button wide" disabled={saving} onClick={() => change({ assignee_id: user.id })}>Assign to me</button>
          )}
          <div className="actions">
            {f.status !== 'fixed' && <button className="pill-button dark wide" disabled={saving} onClick={() => change({ status: 'fixed' })}>Mark as fixed</button>}
            {f.status === 'open' && <button className="pill-button wide" disabled={saving} onClick={() => change({ status: 'ignored' })}>Ignore (false positive)</button>}
            {f.status !== 'open' && <button className="pill-button wide" disabled={saving} onClick={() => change({ status: 'open' })}>Reopen</button>}
          </div>
          <FixNote f={f} />
          {actionError && <p className="error">{actionError}</p>}
        </Panel>
      </div>

      <Panel title="History">
        <ul className="history">
          <li><span>{fmtDateTime(f.first_seen)}</span><strong>Detected</strong><span>{toolName(f.tool)} found it ({f.tool_type})</span></li>
          {f.events.map((e, i) => (
            <li key={i}>
              <span>{fmtDateTime(e.at)}</span>
              <strong>{e.kind === 'status' ? STATUS_WORD[e.detail] ?? e.detail : e.kind === 'assigned' ? 'Assigned' : 'Unassigned'}</strong>
              <span>{e.kind === 'assigned' ? `To ${e.detail}` : ''}{e.by ? `${e.kind === 'assigned' ? ', by' : 'By'} ${e.by}` : ''}</span>
            </li>
          ))}
          <li>
            <span>{fmtDateTime(f.last_seen)}</span>
            <strong>{f.still_reported ? 'Last seen' : 'Not seen since'}</strong>
            <span>{f.still_reported ? `Still in the latest ${toolName(f.tool)} scan (run ${f.run_id})` : 'The latest scan no longer reports it'}</span>
          </li>
        </ul>
      </Panel>
    </>
  )
}

function FixNote({ f }: { f: FindingDetail }) {
  if (f.status === 'fixed' && f.still_reported)
    return <div className="note-box warn"><strong>Waiting for the next scan</strong><br />Push your change: the next pipeline run checks that the problem is gone.</div>
  if (f.status === 'fixed') return <div className="note-box good"><strong>Verified</strong><br />The latest scan no longer reports it.</div>
  if (!f.still_reported) return <div className="note-box">The latest scan no longer reports this. If you fixed it, mark it as fixed.</div>
  return null
}

const capitalize = (s: string) => s.charAt(0).toUpperCase() + s.slice(1)
