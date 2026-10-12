import type { Insight } from '../api'

const LEVEL_LABEL = { high: 'High', medium: 'Medium', good: 'Good' }

export function InsightCard({ insight }: { insight: Insight }) {
  return (
    <div className="insight">
      <div className="insight-head">
        <span className={`badge level-${insight.level}`}>{LEVEL_LABEL[insight.level]}</span>
        <h3>{insight.title}</h3>
      </div>
      <p>{insight.detail}</p>
      {insight.action && <p className="strong">Suggested action: {insight.action}.</p>}
    </div>
  )
}
