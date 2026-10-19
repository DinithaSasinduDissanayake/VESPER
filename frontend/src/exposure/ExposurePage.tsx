// Owner: H.T.D. Fernando — build this page here.
import { useQueue } from '@/api/useQueue'
import { findScore, toPercent } from '@/queue/format'

// Starter: CVEs whose exposure score is high but whose CVSS is not.
// These may be risks that a CVSS-only view would miss.
export function ExposurePage() {
  const items = useQueue()
  if (!items) return <p>Loading…</p>

  const missed = items.filter((item) => {
    const exposure = findScore(item, 'c_graph')?.score ?? 0
    const cvss = item.vulnerability.cvss_base_score ?? 0
    return exposure >= 0.5 && cvss < 9
  })

  return (
    <div>
      <p className="mb-4 text-muted-foreground">
        High exposure, but a lower CVSS score: possibly missed risk.
      </p>
      <ul className="list-disc pl-5">
        {missed.map((item) => (
          <li key={item.vulnerability.cve_id}>
            {item.vulnerability.cve_id}: exposure{' '}
            {toPercent(findScore(item, 'c_graph')?.score ?? 0)}, CVSS{' '}
            {item.vulnerability.cvss_base_score?.toFixed(1) ?? '—'}
          </li>
        ))}
      </ul>
    </div>
  )
}
