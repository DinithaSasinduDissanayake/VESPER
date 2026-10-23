import { Activity, CircleCheck, GitFork, Hash } from 'lucide-react'
import type { StructuralDetails } from './types'

const percent = (value: number) => `${(value * 100).toFixed(0)}%`

export function StructuralSummary({ data }: { data: StructuralDetails }) {
  const score = data.structuralScore
  const available = score.status === 'available' && score.value !== null
  const metrics = [
    { label: 'PageRank percentile', value: available ? percent(score.value!) : 'Unavailable', icon: Activity, note: 'Relative structural importance' },
    { label: 'Observed relationships', value: data.graphFeatures.degree?.toLocaleString() ?? 'Unavailable', icon: GitFork, note: 'Degree · products + weaknesses' },
    { label: 'Raw PageRank', value: data.graphFeatures.pagerankRaw?.toExponential(3) ?? 'Unavailable', icon: Hash, note: 'Unscaled graph centrality' },
    { label: 'Status', value: available ? 'Available' : 'Unavailable', icon: CircleCheck, note: score.status.replaceAll('_', ' ') },
  ]
  return (
    <div className="[&>p]:text-sm">
      <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {metrics.map(({ label, value, icon: Icon, note }, i) => (
          <div key={label} className={`min-w-0 rounded-xl border p-4 ${i === 0 ? 'border-structural-border bg-structural-soft' : 'bg-muted/30'}`}>
            <dt className="flex items-center gap-2 text-sm font-medium"><Icon className="size-4 shrink-0 text-structural" aria-hidden="true" />{label}</dt>
            <dd className={`mt-3 break-words font-semibold tracking-tight tabular-nums ${i === 0 && available ? 'text-4xl text-structural' : 'text-2xl'}`}>{value}</dd>
            <dd className="mt-1 text-sm text-muted-foreground">{note}</dd>
          </div>
        ))}
      </dl>
      {score.reason && <p className="mt-3 rounded-lg border border-dashed p-3 text-sm">{score.reason}</p>}
      <p className="mt-3 text-xs leading-relaxed text-muted-foreground">Structural score represents relative importance within the observed vulnerability–product–weakness graph, not exploitation probability.</p>
    </div>
  )
}
