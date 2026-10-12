import { useEffect, useState } from 'react'

const REFRESH_MS = 5 * 60 * 1000 // reload every 5 minutes, so new scans show up without pressing F5

// Loads data when the inputs change, reloads it quietly every few minutes, and remembers loading / error state.
export function useData<T>(load: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    const run = (quiet: boolean) => {
      if (!quiet) setLoading(true)
      load()
        .then((d) => {
          if (!cancelled) {
            setData(d)
            setError(null)
          }
        })
        .catch((e: Error) => !cancelled && !quiet && setError(e.message))
        .finally(() => !cancelled && setLoading(false))
    }
    run(false)
    const timer = setInterval(() => run(true), REFRESH_MS)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)

  return { data, error, loading }
}
