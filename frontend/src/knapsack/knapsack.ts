export type Vulnerability = {
  cveId: string
  riskScore: number
  modelRank: number
  patchHours: number | null
  criticality: number
  source: Record<string, string>
}

export type PlannedVulnerability = Vulnerability & {
  priorityValue: number
  selected: boolean
  reason: string
}

export type PlannerResponse = {
  patchers: number
  hoursPerPatcher: number
  capacityHours: number
  usedHours: number
  totalPriorityValue: number
  scheduled: PlannedVulnerability[]
  deferred: PlannedVulnerability[]
}

export type RankingInfo = {
  rankingFile: string
  rankingModel: string | null
  modelSelectionStatus: string | null
  synthetic: boolean
  count: number
}

export type ApiRankingResponse = {
  ranking_file: string
  ranking_model: string | null
  model_selection_status: string | null
  synthetic: boolean
  count: number
  vulnerabilities: {
    cve_id: string
    risk_score: number
    model_rank: number
    patch_hours: number | null
    business_criticality: number
  }[]
}

type ApiPlanItem = {
  cve_id: string
  risk_score: number
  model_rank: number
  patch_hours: number | null
  business_criticality: number
  priority_value: number
  selected: boolean
  reason: string
}

export type ApiPlanResponse = {
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
  scheduled: ApiPlanItem[]
  deferred: ApiPlanItem[]
}

export function readRankingResponse(response: ApiRankingResponse): {
  info: RankingInfo
  vulnerabilities: Vulnerability[]
} {
  return {
    info: {
      rankingFile: response.ranking_file,
      rankingModel: response.ranking_model,
      modelSelectionStatus: response.model_selection_status,
      synthetic: response.synthetic,
      count: response.count,
    },
    vulnerabilities: response.vulnerabilities.map((item) => ({
      cveId: item.cve_id,
      riskScore: item.risk_score,
      modelRank: item.model_rank,
      patchHours: item.patch_hours,
      criticality: item.business_criticality,
      source: {
        data_origin: response.synthetic ? 'synthetic' : 'real',
        model_selection_status: response.model_selection_status ?? '',
      },
    })),
  }
}

export function makePlanRequest(
  vulnerabilities: Vulnerability[],
  patchers: number,
  hoursPerPatcher: number,
) {
  return {
    patchers,
    hours_per_patcher: hoursPerPatcher,
    overrides: vulnerabilities.map((item) => ({
      cve_id: item.cveId,
      patch_hours: item.patchHours,
      business_criticality: item.criticality,
    })),
  }
}

export function readPlanResponse(response: ApiPlanResponse): PlannerResponse {
  const mapItem = (item: ApiPlanItem): PlannedVulnerability => ({
    cveId: item.cve_id,
    riskScore: item.risk_score,
    modelRank: item.model_rank,
    patchHours: item.patch_hours,
    criticality: item.business_criticality,
    priorityValue: item.priority_value,
    selected: item.selected,
    reason: item.reason,
    source: {},
  })
  return {
    patchers: response.patchers,
    hoursPerPatcher: response.hours_per_patcher,
    capacityHours: response.capacity_hours,
    usedHours: response.used_hours,
    totalPriorityValue: response.total_priority_value,
    scheduled: response.scheduled.map(mapItem),
    deferred: response.deferred.map(mapItem),
  }
}

export function scheduleCsv(rows: PlannedVulnerability[]): string {
  const quote = (value: string | number) => `"${String(value).replaceAll('"', '""')}"`
  const header = ['cve_id', 'model_rank', 'risk_score', 'business_criticality', 'priority_value', 'patch_hours', 'scheduled_today', 'status']
  const lines = rows.map((row) => [
    row.cveId,
    row.modelRank,
    row.riskScore.toFixed(5),
    row.criticality,
    row.priorityValue.toFixed(5),
    row.patchHours ?? '',
    row.selected ? 'yes' : 'no',
    row.reason,
  ].map(quote).join(','))
  return [header.map(quote).join(','), ...lines].join('\r\n')
}
