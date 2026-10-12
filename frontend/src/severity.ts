import type { Severity } from './api'

// Severity colours from the Figma design, used the same way on every chart, badge and legend.
export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: '#c8233a',
  high: '#ef8a2a',
  medium: '#f2c94c',
  low: '#a8afc7',
  info: '#d6d9e4',
}

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
}
