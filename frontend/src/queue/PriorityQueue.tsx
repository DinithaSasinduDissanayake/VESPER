import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import type { Component, QueueItem, Score, ScoreStatus } from './types'

// Words shown when a component gave no number.
const statusLabels: Record<ScoreStatus, string> = {
  available: '—',
  abstained: 'abstained',
  already_exploited: 'already exploited',
  not_eligible: 'not eligible',
}

function findScore(item: QueueItem, component: Component): Score | undefined {
  return item.scores.find((s) => s.component === component)
}

// The fused score used for ranking, or null when there is none.
function fusedScore(item: QueueItem): number | null {
  return findScore(item, 'd_fusion')?.score ?? null
}

// Highest fused score first; items without one go last.
function rankItems(items: QueueItem[]): QueueItem[] {
  return [...items].sort((x, y) => {
    const a = fusedScore(x)
    const b = fusedScore(y)
    if (a === null && b === null) return 0
    if (a === null) return 1
    if (b === null) return -1
    return b - a
  })
}

// A 0–1 score shown as a whole number from 0 to 100.
function toPercent(value: number): string {
  return Math.round(value * 100).toString()
}

// One component cell: the score, or a muted word saying why there is none.
function ScoreCell({ score }: { score: Score | undefined }) {
  if (score?.score != null) {
    return <TableCell className="text-right">{toPercent(score.score)}</TableCell>
  }
  return (
    <TableCell className="text-right text-muted-foreground" title={score?.reason ?? undefined}>
      {score ? statusLabels[score.status] : '—'}
    </TableCell>
  )
}

export function PriorityQueue({ items }: { items: QueueItem[] }) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Rank</TableHead>
          <TableHead>CVE</TableHead>
          <TableHead>Title</TableHead>
          <TableHead>Vendor / product</TableHead>
          <TableHead className="text-right">Priority</TableHead>
          <TableHead className="text-right">Text</TableHead>
          <TableHead className="text-right">Timing</TableHead>
          <TableHead className="text-right">Exposure</TableHead>
          <TableHead className="text-right">CVSS</TableHead>
          <TableHead className="text-right">EPSS</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rankItems(items).map((item, index) => {
          const { cve_id, description, cvss_base_score, affected } = item.vulnerability
          const fused = fusedScore(item)
          return (
            <TableRow key={cve_id}>
              <TableCell>{index + 1}</TableCell>
              <TableCell className="font-mono">{cve_id}</TableCell>
              <TableCell className="whitespace-normal">{description}</TableCell>
              <TableCell>{affected.map(([vendor, product]) => `${vendor} / ${product}`).join(', ')}</TableCell>
              <TableCell className="text-right font-semibold">
                {fused === null ? '—' : toPercent(fused)}
              </TableCell>
              <ScoreCell score={findScore(item, 'a_text')} />
              <ScoreCell score={findScore(item, 'b_survival')} />
              <ScoreCell score={findScore(item, 'c_graph')} />
              <TableCell className="text-right">{cvss_base_score?.toFixed(1) ?? '—'}</TableCell>
              <TableCell className="text-right">{item.epss?.toFixed(2) ?? '—'}</TableCell>
            </TableRow>
          )
        })}
      </TableBody>
    </Table>
  )
}
