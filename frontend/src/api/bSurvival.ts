// Component B (exploit timing) live API. Backend: src/vesper/api/b_survival.py.

export type Point = [day: number, chance: number]

export type Features = {
  cvss_base_score: number | null
  attack_vector: string
  attack_complexity: string
  privileges_required: string
  user_interaction: string
  public_exploit_at_publication: boolean
  cwe_ids: string[]
}

export type Driver = {
  feature: string
  label: string
  value: number
  coef: number
  hazard_ratio: number // exp(coef): × risk for this feature
  effect: number // coef × (value − average): + raises risk, − lowers it
}

export type Estimate = {
  curve: Point[] // chance of a KEV listing by each day since publication
  by_day: Record<'30' | '90' | '365', number>
  relative_risk: number
  percentile: number // share of eligible CVEs with a lower or equal risk
  band: 'High' | 'Medium' | 'Low'
  drivers: Driver[]
}

export type CveCheck = {
  cve_id: string | null
  status: 'available' | 'already_exploited' | 'not_eligible'
  reason: string | null
  published?: string
  age_days?: number
  features: Features | null
  estimate: Estimate | null
  population: { label: string; curve: Point[] }
  trained_through: string
  note: string
}

export type PlanRow = {
  rank: number
  cve_id: string
  status: CveCheck['status']
  reason: string | null
  p_before_deadline: number | null
  band: Estimate['band'] | null
  main_driver: string | null
  patch_first: boolean
}

export type ModelInfo = {
  trained_through: string
  train_rows: number
  train_events: number
  levels: Record<string, string[]>
  top_cwes: string[]
}

async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(url, init)
  } catch {
    throw new Error('No response from the VESPER API. Is the backend running?')
  }
  const body = await response.json().catch(() => null)
  if (!response.ok) {
    const detail = typeof body?.detail === 'string' ? body.detail : `Request failed (HTTP ${response.status})`
    throw new Error(response.status === 503 ? `Timing model not available: ${detail}` : detail)
  }
  return body as T
}

const post = (body: unknown): RequestInit => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
})

export const getModelInfo = () => requestJson<ModelInfo>('/api/b/model')
export const checkCve = (id: string) => requestJson<CveCheck>(`/api/b/cve/${encodeURIComponent(id.trim())}`)
export const predictWhatIf = (features: Features) => requestJson<CveCheck>('/api/b/predict', post(features))
export const planDeadline = (cveIds: string[], deadlineDays: number) =>
  requestJson<{ deadline_days: number; rows: PlanRow[]; note: string }>(
    '/api/b/plan',
    post({ cve_ids: cveIds, deadline_days: deadlineDays }),
  )
