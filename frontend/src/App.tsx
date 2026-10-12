import { useEffect, useState } from 'react'
import logo from './assets/logo.png'
import { savedSession, signOut, type User } from './auth'
import { Avatar } from './components/ui'
import { href, readHash, type Page, type Route } from './nav'
import DashboardPage from './pages/DashboardPage'
import DevDashboardPage from './pages/DevDashboardPage'
import FindingPage from './pages/FindingPage'
import FindingsPage from './pages/FindingsPage'
import InsightsPage from './pages/InsightsPage'
import ProjectPage from './pages/ProjectPage'
import ProjectsPage from './pages/ProjectsPage'
import RunsPage from './pages/RunsPage'
import SignInPage from './pages/SignInPage'
import TeamPage from './pages/TeamPage'

type NavItem = { page: Page; label: string; also?: Page[] }

// Manager view from the Figma design. "Findings" is extra: the searchable table from FR-14 / FR-15.
const MANAGER_NAV: NavItem[] = [
  { page: 'dashboard', label: 'Dashboard' },
  { page: 'projects', label: 'Projects', also: ['project'] },
  { page: 'findings', label: 'Findings', also: ['finding'] },
  { page: 'runs', label: 'Pipeline Status' },
  { page: 'insights', label: 'Risk Insights' },
]

// Developer view from the Figma design: one project at a time.
const DEVELOPER_NAV: NavItem[] = [
  { page: 'dashboard', label: 'Dashboard', also: ['insights'] },
  { page: 'findings', label: 'Findings', also: ['finding'] },
  { page: 'runs', label: 'Pipeline runs' },
  { page: 'team', label: 'Team' },
]

export default function App() {
  const [user, setUser] = useState<User | null>(() => savedSession()?.user ?? null)
  const [route, setRoute] = useState<Route>(readHash)

  useEffect(() => {
    const onChange = () => {
      setRoute(readHash())
      window.scrollTo(0, 0)
    }
    window.addEventListener('hashchange', onChange)
    return () => window.removeEventListener('hashchange', onChange)
  }, [])

  if (!user) return <SignInPage onSignedIn={setUser} />

  const { page, params } = route
  const developer = user.role === 'developer'
  const nav = developer ? DEVELOPER_NAV : MANAGER_NAV
  // A developer works in one project at a time: the one in the address, else their first.
  const repo = developer ? (params.repo && user.projects.includes(params.repo) ? params.repo : user.projects[0]) : params.repo

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="sidebar-inner">
          <a className="brand" href={href('dashboard')}>
            <div className="brand-text">
              <span className="brand-name">SecFlow</span>
              <span className="brand-sub">Unified DevSecOps Telemetry Portal</span>
              <span className="brand-sponsor">sponsored by Cyberani</span>
            </div>
            <img src={logo} alt="" className="brand-logo" />
          </a>
          <nav>
            {nav.map((n) => (
              <a key={n.page} href={href(n.page, developer ? { repo } : {})}
                className={page === n.page || n.also?.includes(page) ? 'active' : ''}>
                {n.label}
              </a>
            ))}
          </nav>
        </div>
        <div className="sidebar-user">
          <Avatar name={user.name} big />
          <span className="grow">
            {user.name}
            <small>{developer ? 'Developer' : 'Manager'}</small>
          </span>
          <button className="signout" onClick={signOut} title="Sign out" aria-label="Sign out">
            <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" strokeWidth="1.8">
              <path d="M14 5h4a1 1 0 011 1v12a1 1 0 01-1 1h-4M10 8l-4 4 4 4M6 12h10" />
            </svg>
          </button>
        </div>
      </aside>
      <main className="content">
        {developer && !repo ? (
          <p className="empty">You are not in a project yet. Ask your manager to add you (python -m app.users projects).</p>
        ) : developer ? (
          <>
            {page === 'findings' && <FindingsPage params={{ ...params, repo: repo! }} />}
            {page === 'finding' && <FindingPage id={params.id} user={user} />}
            {page === 'runs' && <RunsPage repo={repo} title="Pipeline runs" />}
            {page === 'team' && <TeamPage repo={repo!} projects={user.projects} />}
            {page === 'insights' && <InsightsPage repo={repo} />}
            {!['findings', 'finding', 'runs', 'team', 'insights'].includes(page) && <DevDashboardPage repo={repo!} projects={user.projects} />}
          </>
        ) : (
          <>
            {page === 'dashboard' && <DashboardPage />}
            {page === 'projects' && <ProjectsPage />}
            {page === 'project' && <ProjectPage repo={params.repo} />}
            {page === 'findings' && <FindingsPage params={params} />}
            {page === 'finding' && <FindingPage id={params.id} user={user} />}
            {page === 'runs' && <RunsPage repo={params.repo} />}
            {page === 'insights' && <InsightsPage repo={params.repo} />}
            {page === 'team' && <DashboardPage />}
          </>
        )}
      </main>
    </div>
  )
}
