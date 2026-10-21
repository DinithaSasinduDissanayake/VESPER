import { ArrowDownRight, ArrowUpRight, Equal } from 'lucide-react'
import { toPercent } from '@/queue/format'
import type { StructuralDetails } from './types'

const percent = (value: number) => `${toPercent(value)}%`

export function StructuralCvssComparison({ comparison }: { comparison: StructuralDetails['cvssComparison'] }) {
  if (comparison.available === false) return (
    <section className="rounded-xl border p-5">
      <h4 className="font-semibold">Structural vs CVSS</h4>
      <p className="mt-3 text-sm">Comparison unavailable</p>
      <p className="mt-1 text-xs text-muted-foreground">{comparison.reason}</p>
    </section>
  )
  // Equal values are the similar state; no research acceptance threshold is inferred.
  const direction = Math.sign(comparison.difference)
  const Icon = direction > 0 ? ArrowUpRight : direction < 0 ? ArrowDownRight : Equal
  const label = direction > 0 ? 'Structural ranking higher than CVSS' : direction < 0 ? 'Structural ranking lower than CVSS' : 'Similar structural and CVSS ranking'
  return (
    <section className="rounded-xl border p-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h4 className="font-semibold">Structural vs CVSS</h4>
        <span className="rounded-md bg-muted px-2 py-1 text-xs">Complete-case comparison</span>
      </div>
      <div className="mt-5 grid gap-6 lg:grid-cols-[1fr_1fr]">
        <div className="space-y-4">
          {[
            ['Structural percentile', comparison.structuralPercentile],
            ['CVSS percentile', comparison.cvssPercentile],
          ].map(([label, value]) => (
            <div key={label as string}>
              <div className="mb-2 flex justify-between gap-3 text-xs"><span>{label}</span><strong className="tabular-nums">{percent(value as number)}</strong></div>
              <div role="meter" aria-label={label as string} aria-valuemin={0} aria-valuemax={100} aria-valuenow={(value as number) * 100} className="h-2 overflow-hidden rounded-full bg-muted">
                <div className={`h-full rounded-full ${label === 'Structural percentile' ? 'bg-structural' : 'bg-muted-foreground'}`} style={{ width: percent(value as number) }} />
              </div>
            </div>
          ))}
        </div>
        <div className="rounded-lg bg-muted/40 p-4">
          <div className={`flex items-center gap-2 ${direction > 0 ? 'text-structural' : ''}`}><Icon className="size-5" aria-hidden="true" /><strong className="text-2xl tabular-nums">{direction > 0 ? '+' : ''}{(comparison.difference * 100).toFixed(1)}</strong><span className="text-xs text-muted-foreground">percentage points</span></div>
          <p className="mt-2 text-sm font-medium">{label}</p>
          <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{direction === 0 ? 'The two percentiles are equal in this comparison cohort.' : `Graph structure ranks this CVE ${direction > 0 ? 'higher' : 'lower'} than conventional CVSS severity within the comparison cohort.`}</p>
        </div>
      </div>
      <p className="mt-4 text-xs leading-relaxed text-muted-foreground">Structural and CVSS percentiles may use a different complete-case analysis cohort from the primary structural-score population.</p>
      <p className="mt-1 text-xs text-muted-foreground">{comparison.cohort}</p>
    </section>
  )
}
