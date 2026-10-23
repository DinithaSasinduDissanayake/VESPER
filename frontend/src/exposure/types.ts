import type { ScoreStatus } from '@/queue/types'

export type Evidence<T> =
  | { status: 'supported'; values: T[]; reason: null }
  | { status: 'unavailable' | 'not_evaluated'; values: []; reason: string }

export type VendorProduct = { vendor: string; product: string }

// Percentiles are fractions in [0, 1]. Raw PageRank is a separate quantity.
export type StructuralDetails = {
  cveId: string
  dataSource: 'sample' | 'api'
  structuralScore: {
    value: number | null
    status: ScoreStatus | 'unavailable'
    reason: string | null
    scoreKind: 'ranking_score'
    modelVersion: string
    snapshotDate: string
    population: number | null
  }
  graphFeatures: { pagerankRaw: number | null; degree: number | null }
  relationships: {
    vendorProducts: Evidence<VendorProduct>
    cweIds: Evidence<string>
  }
  cvssComparison:
    | {
        available: true
        structuralPercentile: number
        cvssPercentile: number
        difference: number // Signed fraction, displayed as percentage points.
        cohort: string
      }
    | { available: false; reason: string }
  provenance: {
    referenceTime: string
    graphScope: string
    evidenceStatus: string
    snapshotId?: string
    providerModelVersion?: string
    featureSchemaVersion?: string
    sourcePublishedAt?: string
    sourceModifiedAt?: string
    sourceFile?: string
    providerSha256?: string
    scoresSha256?: string
    analysisSha256?: string | null
    featureProvenance?: string
  }
}

// An API adapter can supply these states later without changing presentation.
export type StructuralDetailsState =
  | { state: 'loading' }
  | { state: 'error'; message: string }
  | { state: 'loaded'; data: StructuralDetails }
