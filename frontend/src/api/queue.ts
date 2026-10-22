import { sampleQueue } from '@/queue/sampleQueue'
import type { QueueItem } from '@/queue/types'

export type PlannerCandidate = {
  cve_id: string
  risk_score: number
  model_rank: number
  patch_hours: number | null
  patch_hours_method: string | null
  patch_severity_tier: string | null
  business_criticality: number
  fusion_score: number | null
  score_a: number | null
  score_b: number | null
  score_c: number | null
  cvss_base_score: number | null
  epss_score: number | null
  status_a: string | null
  status_b: string | null
  status_c: string | null
  reason_a: string | null
  reason_b: string | null
  reason_c: string | null
  signals_used: number | null
  signal_coverage: number | null
  snapshot_date_a: string | null
  snapshot_date_b: string | null
  snapshot_date_c: string | null
  baseline_snapshot_date: string | null
  epss_date: string | null
  data_as_of: string | null
  ranking_model: string | null
  model_selection_status: string | null
}

export type PlannerRanking = {
  ranking_file: string
  ranking_model: string | null
  model_selection_status: string | null
  synthetic: boolean
  count: number
  vulnerabilities: PlannerCandidate[]
}

export type VulnerabilityFacts = {
  cve_id: string
  description: string
  published_at: string
  last_modified_at: string
  cvss_base_score: number | null
  cvss_version: string | null
  cvss_vector: string | null
  cwe_ids: string[]
  affected: [vendor: string, product: string][]
  nvd_status: string
  snapshot_date: string
}

export type PlannerPeriod = 'day' | 'week' | 'month'

export type PlannerOverride = {
  cve_id: string
  patch_hours?: number | null
  business_criticality?: number
}

export type PlannerRequest = {
  patchers: number
  hours_per_patcher: number
  planning_period: PlannerPeriod
  start_date: string
  overrides: PlannerOverride[]
}

export type PlannedCandidate = PlannerCandidate & {
  priority_value: number
  selected: boolean
  reason: string
  planned_date: string | null
}

export type PlannerResponse = {
  ranking_file: string
  ranking_model: string | null
  model_selection_status: string | null
  synthetic: boolean
  total_cves: number
  patchers: number
  hours_per_patcher: number
  planning_period: PlannerPeriod
  start_date: string
  workdays: number
  daily_capacity_hours: number
  capacity_hours: number
  used_hours: number
  total_priority_value: number
  scheduled: PlannedCandidate[]
  deferred: PlannedCandidate[]
  daily_summaries: {
    date: string
    selected_count: number
    used_hours: number
    capacity_hours: number
  }[]
}

async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init)
  const body: unknown = await response.json().catch(() => null)
  if (!response.ok) {
    const detail =
      typeof body === 'object' && body !== null && 'detail' in body
        ? body.detail
        : null
    const message =
      typeof detail === 'string'
        ? detail
        : detail == null
          ? `Request failed (${response.status})`
          : JSON.stringify(detail)
    throw new Error(message)
  }
  return body as T
}

// The one place where pages get queue data.
// Today it returns the sample data. Later it becomes a backend call, e.g.
//   const response = await fetch('/api/queue')
//   return (await response.json()) as QueueItem[]
// The response must match the contract types in queue/types.ts.
export async function getQueue(): Promise<QueueItem[]> {
  return sampleQueue
}

// Component D ranking and patch-plan endpoints live here with the queue data
// access functions, so pages do not make direct network requests.
export function getPlannerRanking(signal?: AbortSignal): Promise<PlannerRanking> {
  return requestJson<PlannerRanking>('/api/d-fusion/ranking', { signal })
}

export function getCveDetails(cveId: string, signal?: AbortSignal): Promise<VulnerabilityFacts> {
  return requestJson<VulnerabilityFacts>(`/api/d-fusion/cves/${encodeURIComponent(cveId)}`, { signal })
}

export async function downloadPlannerRanking(signal?: AbortSignal): Promise<Blob> {
  const response = await fetch('/api/d-fusion/ranking.csv', { signal })
  if (!response.ok) throw new Error(`Could not download ranking (${response.status})`)
  return response.blob()
}

export function createPlannerPlan(
  request: PlannerRequest,
  signal?: AbortSignal,
): Promise<PlannerResponse> {
  return requestJson<PlannerResponse>('/api/d-fusion/knapsack', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
    signal,
  })
}
