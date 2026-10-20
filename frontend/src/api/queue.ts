import { sampleQueue } from '@/queue/sampleQueue'
import type { QueueItem } from '@/queue/types'

export type PlannerCandidate = {
  cve_id: string
  risk_score: number
  model_rank: number
  patch_hours: number | null
  business_criticality: number
}

export type PlannerRanking = {
  ranking_file: string
  ranking_model: string | null
  model_selection_status: string | null
  synthetic: boolean
  count: number
  vulnerabilities: PlannerCandidate[]
}

export type PlannerOverride = {
  cve_id: string
  patch_hours: number | null
  business_criticality: number
}

export type PlannerRequest = {
  patchers: number
  hours_per_patcher: number
  overrides: PlannerOverride[]
}

export type PlannedCandidate = PlannerCandidate & {
  priority_value: number
  selected: boolean
  reason: string
}

export type PlannerResponse = {
  ranking_file: string
  ranking_model: string | null
  model_selection_status: string | null
  synthetic: boolean
  total_cves: number
  patchers: number
  hours_per_patcher: number
  capacity_hours: number
  used_hours: number
  total_priority_value: number
  scheduled: PlannedCandidate[]
  deferred: PlannedCandidate[]
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
