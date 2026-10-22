import type { QueueItem } from '@/queue/types'
import type { StructuralDetails, StructuralDetailsState, VendorProduct } from './types'

// UI fixtures only. No CSV, research output, or validated measurement is used.
const demoProducts: VendorProduct[] = [
  { vendor: 'demo_vendor', product: 'document_processor' },
  { vendor: 'demo_vendor', product: 'document_processor_enterprise' },
  { vendor: 'example_foundation', product: 'content_library' },
  { vendor: 'sample_project', product: 'document_conversion_toolkit' },
  { vendor: 'sample_project', product: 'document_conversion_toolkit_extended_edition' },
  { vendor: 'example_foundation', product: 'content_library_tools' },
]

export function sampleStructuralDetails(
  cveId: string,
  value = 0.97,
): StructuralDetails {
  return {
    cveId,
    dataSource: 'sample',
    structuralScore: {
      value,
      status: 'available',
      reason: null,
      scoreKind: 'ranking_score',
      modelVersion: 'sample-pagerank-percentile-ui-1',
      snapshotDate: '2026-10-15',
      population: 1000,
    },
    graphFeatures: { pagerankRaw: 0.0000428, degree: 12 },
    relationships: {
      vendorProducts: { status: 'supported', values: demoProducts, reason: null },
      cweIds: {
        status: 'supported',
        values: ['CWE-20', 'CWE-74', 'CWE-79', 'CWE-89', 'CWE-94', 'CWE-200'],
        reason: null,
      },
    },
    cvssComparison: {
      available: true,
      structuralPercentile: 0.94,
      cvssPercentile: 0.76,
      difference: 0.18,
      cohort: 'Illustrative complete-case comparison cohort (800 sample records)',
    },
    provenance: {
      referenceTime: '2026-10-15T00:00:00Z',
      graphScope: 'sample-observed-graph-1000-cves',
      evidenceStatus: 'Illustrative relationships; not validated NVD evidence',
    },
  }
}

export type DemoScenario = 'higher' | 'similar' | 'lower' | 'unavailable' | 'not_eligible' | 'loading' | 'error'

export const demoScenarios: { value: DemoScenario; label: string }[] = [
  { value: 'higher', label: 'Structural ranking higher' },
  { value: 'similar', label: 'Equal rankings' },
  { value: 'lower', label: 'Structural ranking lower' },
  { value: 'unavailable', label: 'Score unavailable · partial evidence' },
  { value: 'not_eligible', label: 'Not eligible' },
  { value: 'loading', label: 'Loading preview' },
  { value: 'error', label: 'Error preview' },
]

export function sampleStructuralState(scenario: DemoScenario): StructuralDetailsState {
  if (scenario === 'loading') return { state: 'loading' }
  if (scenario === 'error') return { state: 'error', message: 'Sample error: structural details could not be loaded.' }
  const data = sampleStructuralDetails('CVE-2026-10001')
  if (scenario === 'similar' || scenario === 'lower') {
    const structural = scenario === 'similar' ? 0.76 : 0.58
    data.cvssComparison = {
      available: true, structuralPercentile: structural, cvssPercentile: 0.76,
      difference: structural - 0.76, cohort: 'Illustrative complete-case comparison cohort (800 sample records)',
    }
  }
  if (scenario === 'unavailable' || scenario === 'not_eligible') {
    data.structuralScore = {
      ...data.structuralScore, value: null,
      status: scenario,
      reason: scenario === 'not_eligible' ? 'Sample record is not eligible in this snapshot.' : 'Insufficient supported graph evidence for a structural score.',
    }
    data.graphFeatures = { pagerankRaw: null, degree: null }
    data.cvssComparison = { available: false, reason: 'A compatible complete-case comparison is unavailable.' }
    data.relationships.cweIds = { status: 'unavailable', values: [], reason: 'No supported weakness relationship was extracted. This does not establish that none exists.' }
    if (scenario === 'not_eligible') {
      data.relationships.vendorProducts = { status: 'not_evaluated', values: [], reason: 'Relationships were not evaluated for this sample record.' }
      data.relationships.cweIds = { status: 'not_evaluated', values: [], reason: 'Relationships were not evaluated for this sample record.' }
    }
  }
  return { state: 'loaded', data }
}

export function structuralStateForQueueItem(item: QueueItem): StructuralDetailsState {
  const score = item.scores.find((s) => s.component === 'c_graph')
  const data = sampleStructuralDetails(item.vulnerability.cve_id, score?.score ?? 0.97)
  if (!score || score.status !== 'available' || score.score === null) {
    const unavailable = sampleStructuralState(score?.status === 'not_eligible' ? 'not_eligible' : 'unavailable')
    if (unavailable.state === 'loaded') {
      unavailable.data.cveId = data.cveId
      unavailable.data.structuralScore.status = score?.status ?? 'unavailable'
      unavailable.data.structuralScore.reason = score?.reason ?? 'No sample structural score supplied.'
      return unavailable
    }
  }
  return { state: 'loaded', data }
}
