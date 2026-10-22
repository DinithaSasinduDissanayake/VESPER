import { useEffect, useState } from 'react'
import { getComponentCDetails, type ComponentCResponse } from '@/api/queue'
import type { Evidence, StructuralDetails, StructuralDetailsState } from './types'

function fraction(value: number | null): boolean {
  return value === null || (typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1)
}

function evidence<T>(status: Evidence<T>['status'], values: T[], reason: string | null): Evidence<T> {
  if (status === 'supported' && values.length > 0) return { status, values, reason: null }
  if ((status === 'unavailable' || status === 'not_evaluated') && values.length === 0 && reason) {
    return { status, values: [], reason }
  }
  throw new Error('Component C returned inconsistent relationship evidence.')
}

export function mapComponentCDetails(response: ComponentCResponse): StructuralDetails {
  const available = response.score_status === 'available'
  if (!['available', 'abstained', 'not_eligible', 'already_exploited'].includes(response.score_status)
    || ![response.structural_score, response.raw_pagerank, response.pagerank_comparison_percentile, response.cvss_percentile].every(fraction)
    || response.score_kind !== 'ranking_score'
    || (available ? response.structural_score === null || response.raw_pagerank === null : response.structural_score !== null || response.raw_pagerank !== null || !response.score_reason)
    || (response.degree !== null && (!Number.isInteger(response.degree) || response.degree < 0))) {
    throw new Error('Component C returned invalid structural values or availability.')
  }
  const comparisonAvailable = response.comparison_status === 'available'
  const structural = response.pagerank_comparison_percentile
  const cvss = response.cvss_percentile
  const difference = response.pagerank_cvss_disagreement
  if (comparisonAvailable
    ? structural === null || cvss === null || difference === null || !Number.isFinite(difference) || Math.abs(structural - cvss - difference) > 1e-12
    : structural !== null || cvss !== null || difference !== null) {
    throw new Error('Component C returned inconsistent comparison values.')
  }
  const source = response.provenance
  return {
    cveId: response.cve_id,
    dataSource: 'api',
    structuralScore: {
      value: response.structural_score, status: response.score_status,
      reason: response.score_reason, scoreKind: response.score_kind,
      modelVersion: response.model_version, snapshotDate: response.snapshot_date,
      population: response.scoring_population,
    },
    graphFeatures: { pagerankRaw: response.raw_pagerank, degree: response.degree },
    relationships: {
      vendorProducts: evidence(response.cpe_evidence_status, response.vendor_product_relationships, response.cpe_evidence_reason),
      cweIds: evidence(response.cwe_evidence_status, response.cwe_ids, response.cwe_evidence_reason),
    },
    cvssComparison: comparisonAvailable ? {
      available: true, structuralPercentile: structural!, cvssPercentile: cvss!, difference: difference!,
      cohort: `Complete-case comparison cohort · ${response.comparison_population?.toLocaleString() ?? 'population unavailable'} CVEs`,
    } : { available: false, reason: response.comparison_reason ?? 'No compatible complete-case comparison is available.' },
    provenance: {
      referenceTime: response.reference_time, graphScope: source.graph_scope_id,
      evidenceStatus: `Products: ${response.cpe_evidence_status}; weaknesses: ${response.cwe_evidence_status}`,
      snapshotId: source.snapshot_id, providerModelVersion: source.provider_model_version,
      featureSchemaVersion: source.feature_schema_version,
      sourcePublishedAt: source.source_record_published_at, sourceModifiedAt: source.source_record_last_modified_at,
      sourceFile: source.source_nvd_file, providerSha256: source.provider_sha256,
      scoresSha256: source.scores_sha256, analysisSha256: source.analysis_sha256,
      featureProvenance: source.feature_provenance,
    },
  }
}

// Shared by the hook and request-lifecycle tests. Errors never load fixtures.
export async function requestComponentCDetails(
  cveId: string, signal: AbortSignal, publish: (state: StructuralDetailsState) => void,
): Promise<void> {
  if (signal.aborted) return
  publish({ state: 'loading' })
  try {
    const response = await getComponentCDetails(cveId, signal)
    if (signal.aborted) return
    if (response.cve_id !== cveId) throw new Error('Component C returned a different CVE.')
    publish({ state: 'loaded', data: mapComponentCDetails(response) })
  } catch (error) {
    if (!signal.aborted) publish({ state: 'error', message: error instanceof Error ? error.message : 'Could not load structural relationships.' })
  }
}

export function useComponentCDetails(cveId: string | null, attempt = 0): StructuralDetailsState {
  const [result, setResult] = useState<{ cveId: string | null; attempt: number; resource: StructuralDetailsState }>({ cveId: null, attempt: 0, resource: { state: 'loading' } })
  useEffect(() => {
    if (!cveId) return
    const controller = new AbortController()
    void requestComponentCDetails(cveId, controller.signal, (resource) => setResult({ cveId, attempt, resource }))
    return () => controller.abort()
  }, [cveId, attempt])
  return result.cveId === cveId && result.attempt === attempt ? result.resource : { state: 'loading' }
}
