import { useId, useState } from 'react'
import { ChevronDown, Database, Network } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { StructuralRelationshipGraph } from './StructuralRelationshipGraph'
import { StructuralSummary } from './StructuralSummary'
import { StructuralCvssComparison } from './StructuralCvssComparison'
import { findScore } from '@/queue/format'
import { ScoreSection } from '@/queue/ScoreSection'
import type { QueueItem } from '@/queue/types'
import type { StructuralDetails, StructuralDetailsState } from './types'

function RelationshipEvidence({ data }: { data: StructuralDetails }) {
  const [expandedProducts, setExpandedProducts] = useState(false)
  const [expandedCwes, setExpandedCwes] = useState(false)
  const id = useId()
  const { vendorProducts, cweIds } = data.relationships
  return (
    <div className="grid min-w-0 gap-4 lg:grid-cols-2">
      <section className="min-w-0 rounded-xl border p-5">
        <h4 className="font-semibold">Observed affected-product relationships</h4>
        <p className="mt-1 text-xs text-muted-foreground">Recorded associations in the source evidence.</p>
        {vendorProducts.status === 'supported' ? <>
          <ul id={`${id}-products`} className="mt-4 space-y-2">
            {vendorProducts.values.slice(0, expandedProducts ? undefined : 4).map((pair) => <li key={`${pair.vendor}:${pair.product}`} className="grid min-w-0 gap-1 rounded-lg bg-muted/40 p-3 text-xs"><span className="break-all text-muted-foreground"><span className="font-medium">Vendor</span> · {pair.vendor}</span><span className="break-all font-medium"><span className="font-normal text-muted-foreground">Product · </span>{pair.product}</span></li>)}
          </ul>
          {vendorProducts.values.length > 4 && <Button variant="ghost" size="sm" className="mt-3" aria-expanded={expandedProducts} aria-controls={`${id}-products`} onClick={() => setExpandedProducts(!expandedProducts)}>{expandedProducts ? 'Show less' : `Show all ${vendorProducts.values.length} products`}</Button>}
        </> : <p className="mt-4 text-sm text-muted-foreground">{vendorProducts.reason}</p>}
      </section>
      <section className="min-w-0 rounded-xl border p-5">
        <h4 className="font-semibold">Associated weaknesses</h4>
        <p className="mt-1 text-xs text-muted-foreground">CWE identifiers recorded for this vulnerability.</p>
        {cweIds.status === 'supported' ? <>
          <ul id={`${id}-cwes`} className="mt-4 flex flex-wrap gap-2">{cweIds.values.slice(0, expandedCwes ? undefined : 4).map((cwe) => <li key={cwe} className="rounded-lg border border-structural-border/40 bg-structural-soft/60 px-3 py-2 font-mono text-xs">{cwe}</li>)}</ul>
          {cweIds.values.length > 4 && <Button variant="ghost" size="sm" className="mt-3" aria-expanded={expandedCwes} aria-controls={`${id}-cwes`} onClick={() => setExpandedCwes(!expandedCwes)}>{expandedCwes ? 'Show less' : `Show all ${cweIds.values.length} weaknesses`}</Button>}
        </> : <p className="mt-4 text-sm text-muted-foreground">{cweIds.reason}</p>}
      </section>
    </div>
  )
}

export function ExposureSection({ resource, item }: { resource?: StructuralDetailsState; item?: QueueItem }) {
  const id = useId()
  if (!resource && item) {
    return <ScoreSection title="Exposure" score={findScore(item, 'c_graph')} />
  }
  if (!resource) return null

  return (
    <Card className="min-w-0 gap-5" aria-labelledby={`${id}-title`}>
      <CardHeader className="gap-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex min-w-0 items-center gap-3"><span className="rounded-xl border border-structural-border/40 bg-structural-soft p-2.5 text-structural"><Network className="size-5" aria-hidden="true" /></span><div><h3 id={`${id}-title`} className="text-lg font-semibold tracking-tight">Structural Relationships</h3><p className="mt-1 text-xs text-muted-foreground">CVE–Product–Weakness graph analysis</p></div></div>
          {resource.state === 'loaded' && resource.data.dataSource === 'sample' && <span className="rounded-full border border-dashed bg-muted/40 px-3 py-1 text-[10px] font-semibold uppercase tracking-wider">Sample / demo data</span>}
        </div>
      </CardHeader>
      <CardContent className="min-w-0 space-y-5">
        {resource.state === 'loading' && <p role="status" className="rounded-xl border border-dashed p-8 text-muted-foreground">Loading structural relationships…</p>}
        {resource.state === 'error' && <div role="alert" className="rounded-xl border p-6"><p className="font-medium">Structural relationships could not be loaded</p><p className="mt-2 text-sm text-muted-foreground">{resource.message}</p></div>}
        {resource.state === 'loaded' && <>
          {resource.data.dataSource === 'sample' && <p className="rounded-lg border border-dashed px-3 py-2 text-xs leading-relaxed text-muted-foreground">Illustrative UI fixtures only. All scores, relationships and provenance shown here are sample data, including when the selected CVE ID is real. They are not validated research results.</p>}
          <StructuralSummary data={resource.data} />
          <StructuralRelationshipGraph data={resource.data} />
          <StructuralCvssComparison comparison={resource.data.cvssComparison} />
          <RelationshipEvidence key={resource.data.cveId} data={resource.data} />
          <details className="group rounded-xl border bg-muted/20 p-4">
            <summary className="flex cursor-pointer list-none items-center gap-2 rounded-sm font-medium outline-none focus-visible:ring-2 focus-visible:ring-ring"><Database className="size-4" aria-hidden="true" />About this signal & provenance<ChevronDown className="ml-auto size-4 group-open:rotate-180" aria-hidden="true" /></summary>
            <dl className="mt-4 grid min-w-0 gap-3 text-xs sm:grid-cols-2">
              {[
                ['Reference time', resource.data.provenance.referenceTime],
                ['Snapshot date', resource.data.structuralScore.snapshotDate],
                ['Graph scope', resource.data.provenance.graphScope],
                ['Model version', resource.data.structuralScore.modelVersion],
                ['Score population', resource.data.structuralScore.population?.toLocaleString() ?? 'Unavailable'],
                ['Evidence status', resource.data.provenance.evidenceStatus],
                ['Product evidence', resource.data.relationships.vendorProducts.status],
                ['Weakness evidence', resource.data.relationships.cweIds.status],
              ].map(([label, value]) => <div key={label} className="min-w-0"><dt className="text-muted-foreground">{label}</dt><dd className="mt-1 break-all font-medium">{value}</dd></div>)}
            </dl>
            <p className="mt-4 text-xs leading-relaxed text-muted-foreground">This signal measures structural importance within the observed vulnerability–product–weakness graph. It is not an exploitation probability.</p>
            <p className="mt-2 text-xs leading-relaxed text-muted-foreground">Relationship evidence describes recorded vulnerability associations; it does not represent an organization's deployed network.</p>
          </details>
        </>}
      </CardContent>
    </Card>
  )
}
