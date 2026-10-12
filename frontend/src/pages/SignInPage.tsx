import { useState, type FormEvent } from 'react'
import logo from '../assets/logo.png'
import { api } from '../api'
import { saveSession, type User } from '../auth'

// Sign in (Figma): navy brand half on the left, the form on the right. Accounts are made by an admin
// with "python -m app.users add" (there is no sign-up page on purpose).
export default function SignInPage({ onSignedIn }: { onSignedIn: (user: User) => void }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const { token, user } = await api.login(email, password)
      saveSession(token, user)
      onSignedIn(user)
    } catch (err) {
      const msg = (err as Error).message
      setError(/fetch|network/i.test(msg) ? 'Could not reach the portal. Is the backend running?' : msg)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="signin">
      <div className="signin-brand">
        <div className="signin-brand-text">
          <span className="signin-name">SecFlow</span>
          <span className="signin-sub"><i />Unified DevSecOps Telemetry Portal</span>
          <span className="signin-sponsor">sponsored by Cyberani</span>
        </div>
        <img src={logo} alt="" />
      </div>
      <form className="signin-form" onSubmit={submit}>
        <h1>Sign in</h1>
        <label>
          Work email
          <input type="email" autoComplete="username" placeholder="name@cyberani.sa" value={email}
            onChange={(e) => setEmail(e.target.value)} required />
        </label>
        <label>
          Password
          <input type="password" autoComplete="current-password" placeholder="••••••••" value={password}
            onChange={(e) => setPassword(e.target.value)} required />
        </label>
        {error && <p className="signin-error" role="alert">{error}</p>}
        <button type="submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
      </form>
    </div>
  )
}
