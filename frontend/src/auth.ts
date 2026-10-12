// The signed-in person. The sign-in token is kept in this browser (localStorage) so a refresh keeps you signed in;
// "Sign out" removes it. The backend checks the token on every request.
export interface User {
  id: number
  name: string
  email: string
  role: 'manager' | 'developer'
  projects: string[]
}

const KEY = 'secflow-session'

export function savedSession(): { token: string; user: User } | null {
  try {
    const raw = localStorage.getItem(KEY)
    return raw ? JSON.parse(raw) : null
  } catch {
    return null
  }
}

export function saveSession(token: string, user: User) {
  try {
    localStorage.setItem(KEY, JSON.stringify({ token, user }))
  } catch {
    /* private window: you stay signed in until the tab closes */
  }
  memory = { token, user }
}

let memory = savedSession()

export function token(): string | null {
  return memory?.token ?? null
}

export function signOut() {
  try {
    localStorage.removeItem(KEY)
  } catch {
    /* nothing saved */
  }
  memory = null
  window.location.hash = '#/'
  window.location.reload()
}
