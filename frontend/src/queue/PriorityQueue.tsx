import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { affectedText, findScore, fusedScore, statusLabels, toPercent } from './format'
import type { QueueItem, Score } from './types'

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

type PriorityQueueProps = {
  items: QueueItem[]
  onSelect: (cveId: string) => void
}

export function PriorityQueue({ items, onSelect }: PriorityQueueProps) {
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
          const { cve_id, description, cvss_base_score } = item.vulnerability
          const fused = fusedScore(item)
          return (
            // Rows open the detail view by click or by Enter (tabIndex makes them focusable).
            <TableRow
              key={cve_id}
              tabIndex={0}
              className="cursor-pointer"
              onClick={() => onSelect(cve_id)}
              onKeyDown={(e) => e.key === 'Enter' && onSelect(cve_id)}
            >
              <TableCell>{index + 1}</TableCell>
              <TableCell className="font-mono">{cve_id}</TableCell>
              <TableCell className="whitespace-normal">{description}</TableCell>
              <TableCell>{affectedText(item)}</TableCell>
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
