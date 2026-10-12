// Talks to the FastAPI backend. Change the address with VITE_API_URL in frontend/.env.
// While developing (npm run dev, port 5173) the backend is on localhost:8000. When the backend serves the
// built dashboard itself (the shared link), the API is on the same address as the page.
const SAME_ORIGIN = !import.meta.env.VITE_API_URL && window.location.port !== '5173'
export const API_URL = import.meta.env.VITE_API_URL ?? (SAME_ORIGIN ? window.location.origin : 'http://localhost:8000')

import { signOut, token, type User } from './auth'

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const
export type Severity = (typeof SEVERITIES)[number]
export type SeverityCounts = Record<Severity, number>

export interface Finding {
  id: number
  repo: string
  run_id: string
  tool: string
  tool_type: string
  rule_id: string
  title: string
  description: string | null
  severity: Severity
  cwe: string | null
  file: string | null
  line: number | null
  status: string
  first_seen: string
  last_seen: string
  assignee_id: number | null
  assignee_name: string | null
}

export interface FindingDetail extends Finding {
  still_reported: boolean
  type_name: string
  how_to_fix: string
  members: { id: number; name: string }[]
  events: { kind: string; detail: string; at: string; by: string | null }[]
}

export interface Team {
  repo: string
  members: { id: number; name: string; you: boolean; open: number; fixed_30d: number; last_active: string | null }[]
  activity: { at: string; who: string | null; text: string; finding_id: number | null; status: string | null }[]
}

export interface Run {
  id: number
  repo: string
  run_id: string
  branch: string
  commit_sha: string
  status: string
  run_url: string | null
  started_at: string | null
}

export interface ToolCount extends SeverityCounts {
  tool: string
  tool_type: string
  total: number
}

export interface ProjectCount extends SeverityCounts {
  repo: string
  open: number
  tools: string[]
  last_run: string | null
  pass_rate: number | null
}

export interface Insight {
  level: 'high' | 'medium' | 'good'
  title: string
  detail: string
  action: string
  count: number
}

export interface Dashboard {
  projects: string[]
  repo: string | null
  open_findings: number
  found_total: number
  new_last_7d: number
  critical_open: number
  high_open: number
  still_reported: number
  resolved: number
  mean_days_to_fix: number | null
  runs_total: number
  runs_passed: number
  pass_rate: number | null
  by_severity: SeverityCounts
  by_tool: ToolCount[]
  by_tool_type: Record<string, number>
  trend: ({ date: string } & SeverityCounts)[]
  compare: ProjectCount[]
  insights: Insight[]
  repeated_types: { type: string; count: number }[]
}

type Params = Record<string, string | number | undefined | null>

async function request<T>(method: string, path: string, params: Params = {}, body?: unknown) {
  const url = new URL(path, API_URL)
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, String(v))
  }
  const headers: Record<string, string> = {}
  // ngrok shows a "you are about to visit" page to browsers; this header skips it for data requests.
  if (SAME_ORIGIN) headers['ngrok-skip-browser-warning'] = '1'
  if (token()) headers.Authorization = `Bearer ${token()}`
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  const res = await fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) })
  if (res.status === 401 && token() && !path.startsWith('/api/auth/login')) signOut() // expired: sign in again
  if (!res.ok) {
    const detail = await res.json().then((j) => j.detail, () => null)
    throw new Error(typeof detail === 'string' ? detail : `${res.status} ${res.statusText} from ${url.pathname}`)
  }
  const total = res.headers.get('X-Total-Count')
  return { data: (await res.json()) as T, total: total === null ? null : Number(total) }
}

const get = <T,>(path: string, params: Params = {}) => request<T>('GET', path, params)

export const api = {
  dashboard: (repo?: string) => get<Dashboard>('/api/dashboard', { repo }).then((r) => r.data),
  findings: (params: Params) => get<Finding[]>('/api/findings', params),
  runs: (params: Params) => get<Run[]>('/api/runs', params).then((r) => r.data),
  finding: (id: number | string) => get<FindingDetail>(`/api/findings/${id}`).then((r) => r.data),
  updateFinding: (id: number, change: { assignee_id?: number | null; status?: string }) =>
    request<Finding>('PATCH', `/api/findings/${id}`, {}, change).then((r) => r.data),
  team: (repo: string) => get<Team>('/api/team', { repo }).then((r) => r.data),
  login: (email: string, password: string) =>
    request<{ token: string; user: User }>('POST', '/api/auth/login', {}, { email, password }).then((r) => r.data),
}

// ---- small formatting helpers shared by the pages
export function fmtDate(iso: string | null): string {
  if (!iso) return '-'
  const d = new Date(iso.endsWith('Z') || iso.includes('+') ? iso : iso + 'Z') // backend stores UTC
  return d.toLocaleDateString(undefined, { day: 'numeric', month: 'short' })
}

export function fmtDateTime(iso: string | null): string {
  if (!iso) return '-'
  const d = new Date(iso.endsWith('Z') || iso.includes('+') ? iso : iso + 'Z')
  return d.toLocaleString(undefined, { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })
}

export function location(f: Pick<Finding, 'file' | 'line'>): string {
  if (!f.file) return ''
  return f.line ? `${f.file}:${f.line}` : f.file
}
