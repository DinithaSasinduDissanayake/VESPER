// Mirrors src/vesper/contracts/score.py — keep in sync.
// Python datetime and date values arrive as ISO 8601 strings.

export type Component = 'a_text' | 'b_survival' | 'c_graph' | 'd_fusion'

export type ScoreKind = 'ranking_score' | 'validated_probability'

export type ScoreStatus =
  | 'available'
  | 'abstained'
  | 'already_exploited'
  | 'not_eligible'

export type Score = {
  cve_id: string
  component: Component
  decision_time: string
  horizon_days: number
  score: number | null // a number only when status is 'available'
  score_kind: ScoreKind
  status: ScoreStatus
  reason: string | null
  model_version: string
  trained_through: string | null
  snapshot_date: string
}

// The fields of src/vesper/contracts/vulnerability.py that the queue shows.
export type Vulnerability = {
  cve_id: string
  description: string
  cvss_base_score: number | null
  affected: [vendor: string, product: string][]
}

// One queue row. EPSS is not in the backend contract yet.
export type QueueItem = {
  vulnerability: Vulnerability
  epss: number | null
  scores: Score[]
}
