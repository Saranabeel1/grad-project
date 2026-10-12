export type Page = 'dashboard' | 'projects' | 'project' | 'findings' | 'finding' | 'runs' | 'insights' | 'team'

const PAGES: Page[] = ['dashboard', 'projects', 'project', 'findings', 'finding', 'runs', 'insights', 'team']

// The address bar keeps the page and its filters (for example #/findings?repo=Project%20G&severity=high),
// so the browser Back button works and a view can be bookmarked.
export interface Route {
  page: Page
  params: Record<string, string>
}

export function readHash(): Route {
  const [path, query = ''] = window.location.hash.replace(/^#\/?/, '').split('?')
  const page = PAGES.includes(path as Page) ? (path as Page) : 'dashboard'
  return { page, params: Object.fromEntries(new URLSearchParams(query)) }
}

export function href(page: Page, params: Record<string, string | undefined> = {}): string {
  const clean = Object.fromEntries(Object.entries(params).filter(([, v]) => v)) as Record<string, string>
  const query = new URLSearchParams(clean).toString()
  return `#/${page}${query ? `?${query}` : ''}`
}

export function go(page: Page, params: Record<string, string | undefined> = {}) {
  window.location.hash = href(page, params).slice(1)
}
