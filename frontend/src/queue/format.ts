import type { Component, QueueItem, Score, ScoreStatus } from './types'

// Plain words for each status. The table shows them when there is no number.
export const statusLabels: Record<ScoreStatus, string> = {
  available: 'available',
  abstained: 'abstained',
  already_exploited: 'already exploited',
  not_eligible: 'not eligible',
}

export function findScore(item: QueueItem, component: Component): Score | undefined {
  return item.scores.find((s) => s.component === component)
}

// The fused score used for ranking, or null when there is none.
export function fusedScore(item: QueueItem): number | null {
  return findScore(item, 'd_fusion')?.score ?? null
}

// A 0–1 score shown as a whole number from 0 to 100.
export function toPercent(value: number): string {
  return Math.round(value * 100).toString()
}

// "a, b / c" list of the affected vendor / product pairs.
export function affectedText(item: QueueItem): string {
  return item.vulnerability.affected.map(([vendor, product]) => `${vendor} / ${product}`).join(', ')
}
