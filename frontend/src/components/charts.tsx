import { Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { SEVERITIES, fmtDate, type Dashboard, type Severity } from '../api'
import { toolName, trendPoints } from '../labels'
import { SEVERITY_COLOR, SEVERITY_LABEL } from '../severity'
import { Meter } from './ui'

const axis = { stroke: '#7d8299', fontSize: 12, tickLine: false, axisLine: false } as const

// The four severities from the report are always listed; Info only when there is some.
function shown(counts: Record<Severity, number>): Severity[] {
  return SEVERITIES.filter((s) => s !== 'info' || counts.info > 0)
}

export function SeverityDonut({ counts }: { counts: Record<Severity, number> }) {
  const total = SEVERITIES.reduce((n, s) => n + counts[s], 0)
  const data = shown(counts).map((s) => ({ name: SEVERITY_LABEL[s], value: counts[s], severity: s }))
  return (
    <div className="donut-wrap">
      <div className="donut">
        <ResponsiveContainer width="100%" height={170}>
          <PieChart>
            <Pie data={data.filter((d) => d.value > 0)} dataKey="value" nameKey="name" innerRadius={56} outerRadius={80}
              startAngle={90} endAngle={-270} stroke="#fff" strokeWidth={2} isAnimationActive={false}>
              {data.filter((d) => d.value > 0).map((d) => <Cell key={d.severity} fill={SEVERITY_COLOR[d.severity]} />)}
            </Pie>
            <Tooltip formatter={(v) => [v, 'open']} />
          </PieChart>
        </ResponsiveContainer>
        <div className="donut-center">
          <strong>{total.toLocaleString()}</strong>
          <span>open</span>
        </div>
      </div>
      <ul className="legend-list">
        {data.map((d) => (
          <li key={d.severity}>
            <span className="square" style={{ background: SEVERITY_COLOR[d.severity] }} />
            {d.name}
            <b>{d.value.toLocaleString()}</b>
          </li>
        ))}
      </ul>
    </div>
  )
}

// Severity as bars, for the project page ("Open by severity").
export function SeverityMeters({ counts }: { counts: Record<Severity, number> }) {
  const max = Math.max(...SEVERITIES.map((s) => counts[s]), 1)
  return (
    <ul className="meters">
      {shown(counts).map((s) => (
        <li key={s}>
          <span className="meter-label">{SEVERITY_LABEL[s]}</span>
          <Meter value={counts[s]} max={max} color={SEVERITY_COLOR[s]} />
          <b>{counts[s].toLocaleString()}</b>
        </li>
      ))}
    </ul>
  )
}

export function TrendDirection({ trend }: { trend: Dashboard['trend'] }) {
  const pts = trendPoints(trend)
  if (pts.length < 2) return null
  const first = pts[0].total
  const last = pts[pts.length - 1].total
  if (last < first) return <span className="direction good">Improving</span>
  if (last > first) return <span className="direction bad">Getting worse</span>
  return <span className="direction">No change</span>
}

export function TrendLine({ trend }: { trend: Dashboard['trend'] }) {
  const pts = trendPoints(trend)
  return (
    <ResponsiveContainer width="100%" height={190}>
      <AreaChart data={pts} margin={{ top: 10, right: 12, left: -16, bottom: 0 }}>
        <defs>
          <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#2f55e4" stopOpacity={0.12} />
            <stop offset="100%" stopColor="#2f55e4" stopOpacity={0.04} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="#eceef4" vertical={false} />
        <XAxis dataKey="date" {...axis} tickFormatter={(d) => fmtDate(d)} interval="preserveStartEnd" minTickGap={16} />
        <YAxis {...axis} allowDecimals={false} />
        <Tooltip labelFormatter={(d) => fmtDate(String(d))} formatter={(v) => [v, 'findings reported']} />
        <Area type="linear" dataKey="total" stroke="#2f55e4" strokeWidth={2.5} fill="url(#trendFill)"
          dot={{ r: 4, fill: '#2f55e4', stroke: '#2f55e4' }} activeDot={{ r: 6 }} isAnimationActive={false} />
      </AreaChart>
    </ResponsiveContainer>
  )
}

const TYPE_ORDER = ['SAST', 'SCA', 'IAC', 'DAST', 'SECRETS']
const TYPE_LABEL: Record<string, string> = { SAST: 'SAST', SCA: 'SCA', IAC: 'IaC', DAST: 'DAST', SECRETS: 'Secrets' }

export function ToolTypeBars({ byTool }: { byTool: Dashboard['by_tool'] }) {
  const types = TYPE_ORDER.map((type) => {
    const tools = byTool.filter((t) => t.tool_type === type)
    return { type, total: tools.reduce((n, t) => n + t.total, 0), tools: tools.map((t) => t.tool) }
  }).filter((t) => t.total > 0)
  const max = Math.max(...types.map((t) => t.total), 1)
  return (
    <ul className="meters typed">
      {types.map((t) => (
        <li key={t.type}>
          <span className="meter-label">
            <b>{TYPE_LABEL[t.type]}</b>
            <small>{t.tools.map(toolName).join(', ')}</small>
          </span>
          <Meter value={t.total} max={max} />
          <b>{t.total.toLocaleString()}</b>
        </li>
      ))}
    </ul>
  )
}
