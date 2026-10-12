import type { ReactNode } from 'react'
import { API_URL, type Severity } from '../api'
import { SEVERITY_LABEL } from '../severity'

export function SeverityBadge({ severity, count }: { severity: Severity; count?: number }) {
  return (
    <span className={`badge sev-${severity}`}>
      {count !== undefined && `${count} `}
      {SEVERITY_LABEL[severity] ?? severity}
    </span>
  )
}

const STATUS_LABEL: Record<string, string> = {
  success: 'Passed',
  failure: 'Failed',
  in_progress: 'Running',
  open: 'Open',
  fixed: 'Fixed',
  ignored: 'Ignored',
}

export function StatusBadge({ status }: { status: string }) {
  return <span className={`badge status-${status}`}>{STATUS_LABEL[status] ?? status}</span>
}

export function Panel({ title, action, children, className = '' }: {
  title?: ReactNode
  action?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <section className={`panel ${className}`}>
      {(title || action) && (
        <header className="panel-head">
          {title && <h2>{title}</h2>}
          {action}
        </header>
      )}
      {children}
    </section>
  )
}

// Icons from the design, drawn as simple inline SVGs.
const ICONS: Record<string, ReactNode> = {
  shield: <path d="M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6l7-3zm-1.2 11.6l4.9-4.9-1.4-1.4-3.5 3.5-1.6-1.6-1.4 1.4 3 3z" fill="currentColor" />,
  branch: (
    <g fill="none" stroke="currentColor" strokeWidth="1.8">
      <circle cx="7" cy="5" r="2.2" /><circle cx="7" cy="19" r="2.2" /><circle cx="17" cy="9" r="2.2" />
      <path d="M7 7.2v9.6M17 11.2c0 3-3 3.8-10 5.6" />
    </g>
  ),
  clock: (
    <g fill="none" stroke="currentColor" strokeWidth="1.8">
      <circle cx="12" cy="12" r="8" /><path d="M12 7.5V12l3 2" />
    </g>
  ),
  person: (
    <g fill="none" stroke="currentColor" strokeWidth="1.8">
      <circle cx="12" cy="8.5" r="3.5" /><path d="M5 20c.8-3.6 3.6-5.5 7-5.5s6.2 1.9 7 5.5" />
    </g>
  ),
  warning: (
    <g fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round">
      <path d="M12 4l9 16H3l9-16z" /><path d="M12 10v4.5M12 17v.5" />
    </g>
  ),
}

export function StatCard({ icon, tone = 'blue', label, value, unit, delta, note, ring }: {
  icon?: keyof typeof ICONS | string
  tone?: 'red' | 'blue'
  label: string
  value: ReactNode
  unit?: string
  delta?: number
  note?: ReactNode
  ring?: number | null
}) {
  return (
    <div className="stat">
      {icon && (
        <span className={`stat-icon tone-${tone}`}>
          <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true">{ICONS[icon]}</svg>
        </span>
      )}
      <div className="stat-body">
        <div className="stat-label">{label}</div>
        <div className="stat-value">
          {value}
          {unit && <span className={unit === '%' ? 'stat-unit tight' : 'stat-unit'}>{unit}</span>}
          {delta ? <span className="stat-delta" title="new open findings in the last 7 days">↑ {delta}</span> : null}
        </div>
        {note && <div className="stat-note">{note}</div>}
      </div>
      {ring !== undefined && ring !== null && <PassRing percent={ring} />}
    </div>
  )
}

function PassRing({ percent }: { percent: number }) {
  const r = 22
  const c = 2 * Math.PI * r
  return (
    <svg className="ring" viewBox="0 0 56 56" width="56" height="56" role="img" aria-label={`${percent}% passed`}>
      <circle cx="28" cy="28" r={r} fill="none" stroke="#eceef4" strokeWidth="6" />
      <circle cx="28" cy="28" r={r} fill="none" stroke="#6bdc8b" strokeWidth="6" strokeLinecap="round"
        strokeDasharray={`${(c * percent) / 100} ${c}`} transform="rotate(-90 28 28)" />
    </svg>
  )
}

// A plain horizontal bar on a light track, like the design's "Findings by tool type" and "Projects compared".
export function Meter({ value, max, color = 'var(--blue)' }: { value: number; max: number; color?: string }) {
  const pct = max ? Math.max(value ? 3 : 0, (100 * value) / max) : 0
  return (
    <div className="meter" title={String(value)}>
      <div style={{ width: `${pct}%`, background: color }} />
    </div>
  )
}

export function Avatar({ name, big = false }: { name: string; big?: boolean }) {
  const letter = name.replace(/^Project\s+/i, '').charAt(0).toUpperCase()
  const hues = ['#8fb0f7', '#73d68f', '#f5a3b0', '#f6d66f', '#c5b4f5']
  const hue = hues[[...name].reduce((n, ch) => n + ch.charCodeAt(0), 0) % hues.length]
  return <span className={big ? 'avatar big' : 'avatar'} style={{ background: hue }} title={name}>{letter}</span>
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>
}

export function Loading() {
  return <p className="loading">Loading…</p>
}

export function ErrorBox({ message }: { message: string }) {
  if (!/fetch|network/i.test(message)) return <div className="error">{message}</div> // the backend answered
  return (
    <div className="error">
      <strong>Could not reach the backend.</strong> {message}
      <br />
      Check that it is running at <code>{API_URL}</code> (open <code>{API_URL}/docs</code> in your browser).
    </div>
  )
}
