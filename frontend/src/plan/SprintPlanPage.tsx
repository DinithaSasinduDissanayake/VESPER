// Owner: B.L. Beminiwatte — build this page here.
// The real optimiser is Buwani's knapsack (PR #14): POST /api/d-fusion/knapsack
// with { patchers, hours_per_patcher }. It returns `scheduled` and `deferred`
// lists and `used_hours`. Replace the greedy placeholder below with that call.
import { useState } from 'react'
import { useQueue } from '@/api/useQueue'
import { fusedScore, toPercent } from '@/queue/format'

// PLACEHOLDER: every CVE is assumed to take the same time to patch.
const PLACEHOLDER_HOURS_PER_CVE = 4

export function SprintPlanPage() {
  const items = useQueue()
  const [hours, setHours] = useState(20)
  if (!items) return <p>Loading…</p>

  // Highest priority first; take CVEs while they still fit in the hours.
  const ranked = [...items].sort((x, y) => (fusedScore(y) ?? -1) - (fusedScore(x) ?? -1))
  const count = Math.min(ranked.length, Math.floor(hours / PLACEHOLDER_HOURS_PER_CVE))
  const selected = ranked.slice(0, count)

  return (
    <div className="flex flex-col gap-4">
      <label className="flex items-center gap-2">
        Engineering hours this week
        <input
          type="number"
          min={0}
          value={hours}
          onChange={(e) => setHours(Number(e.target.value))}
          className="w-24 rounded-md border px-2 py-1"
        />
      </label>
      <p className="text-muted-foreground">
        Hours used: {count * PLACEHOLDER_HOURS_PER_CVE} of {hours} (placeholder estimate of{' '}
        {PLACEHOLDER_HOURS_PER_CVE} hours per CVE).
      </p>
      <ol className="list-decimal pl-5">
        {selected.map((item) => {
          const fused = fusedScore(item)
          return (
            <li key={item.vulnerability.cve_id}>
              {item.vulnerability.cve_id} (priority {fused === null ? '—' : toPercent(fused)})
            </li>
          )
        })}
      </ol>
    </div>
  )
}
