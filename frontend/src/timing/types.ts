// Shape of public/demo/exploit_timing.json, written by
// src/vesper/components/b_survival/frontend_export.py — keep in sync.

import type { ScoreStatus } from '@/queue/types'

export type Interval = [lower: number, upper: number]

export type EvidenceItem = {
  kind: 'published' | 'exploit' | 'kev'
  date: string
  label: string
  source?: 'exploitdb'
  url?: string
}

export type Factor = {
  feature: string
  label: string
  value: number
  hazard_ratio: number
  log_effect: number // coef × (value − train mean): effect on the log relative risk
}

export type TimingDetail = {
  cve_id: string
  decision_time: string
  trained_through: string
  model_version: string
  published: string
  age_days: number
  cvss: number | null
  cwe: string[]
  status: ScoreStatus
  reason: string | null
  raw_30d: number | null
  percentile: number | null
  rank: number | null
  rank_of: number
  survival: number[] | null // S(age + d) / S(age) for d = 0 … horizon
  evidence: EvidenceItem[] // only items dated before the decision time
  kev: { date: string; after_decision: boolean } | null
  factors: Factor[]
  // Plain-language fields
  level: Level | null // null when there is no score
  reasons: string[]
  vendor: string | null
  product: string | null
  description: string | null
  nvd_url: string
}

export type Level = 'High' | 'Medium' | 'Low'

export type RecentKev = {
  cve_id: string
  date_added: string
  vendor: string | null
  product: string | null
  name: string | null
  nvd_url: string
}

export type ModelMetric = {
  c_index: number
  c_index_ci: Interval
  p_at_100: number
  p_at_100_ci: Interval
  train_events: number
  test_events: number
}

export type Difference = {
  cohort: string
  cutoff: string
  difference: number
  ci: Interval
  excludes_zero: boolean
  train_events: number
}

export type HazardRatio = {
  feature: string
  label: string
  hazard_ratio: number
  ci: Interval
  p_value: number
}

export type Band = {
  start_day: number
  end_day: number | null
  train_listings: number
  rate_per_day: number
}

export type BacktestRow = {
  cve_id: string
  b_rank: number
  cvss_rank: number
  cvss: number | null
}

export type TimingData = {
  meta: {
    model_version: string
    raw_model_version: string
    decision_time: string
    trained_through: string
    backtest_decision_time: string
    snapshot_date: string
    horizon_days: number
    cohort: string
    generated_at: string
    code_version: string
    note: string
    sample_queue_missing: string[]
  }
  results: {
    main_cutoff: string
    main: Record<'post_kev' | 'full', { cox: ModelMetric; cvss: ModelMetric; difference: Difference }>
    differences: Difference[]
    hazard_ratios: HazardRatio[]
    bands: Band[]
    bands_model_version: string
    kaplan_meier: { cohort: string; rows: number; events: number; points: [day: number, survival: number][] }
  }
  levels: {
    rule: string
    cutoffs: Record<'High' | 'Medium', number>
    counts: Record<Level, number>
  }
  recent_kev: { window_days: number; count: number; items: RecentKev[] }
  top: string[]
  cves: {
    current: Record<string, TimingDetail>
    backtest: Record<string, TimingDetail>
  }
  backtest: {
    decision_time: string
    window_days: number
    listed: number
    listed_by_status: Record<string, number>
    listed_published_after_decision: number
    scored: number
    available_population: number
    top_counts: Record<string, { b: number; cvss: number }>
    rank_note: string
    per_cve: BacktestRow[]
  }
}
