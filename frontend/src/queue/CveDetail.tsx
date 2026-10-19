import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { affectedText, findScore, fusedScore, statusLabels, toPercent } from './format'
import type { Component, QueueItem, Score } from './types'

// User-facing name of each section, in display order.
const sections: [Component, string][] = [
  ['a_text', 'Text signal'],
  ['b_survival', 'Exploit timing'],
  ['c_graph', 'Exposure'],
  ['d_fusion', 'Fusion'],
]

// One section: the full Score, or a placeholder when there is no number.
function ScoreSection({ title, score }: { title: string; score: Score | undefined }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent>
        {score?.score == null ? (
          <p className="text-muted-foreground">
            {score ? statusLabels[score.status] : 'Not available yet'}
            {score?.reason && ` — ${score.reason}`}
          </p>
        ) : (
          <dl className="grid grid-cols-2 gap-x-4 gap-y-1">
            <dt className="text-muted-foreground">Score</dt>
            <dd className="font-semibold">{toPercent(score.score)}</dd>
            <dt className="text-muted-foreground">Status</dt>
            <dd>{statusLabels[score.status]}</dd>
            {score.reason && (
              <>
                <dt className="text-muted-foreground">Reason</dt>
                <dd>{score.reason}</dd>
              </>
            )}
            <dt className="text-muted-foreground">Horizon</dt>
            <dd>{score.horizon_days} days</dd>
            <dt className="text-muted-foreground">Decision time</dt>
            <dd>{score.decision_time}</dd>
            <dt className="text-muted-foreground">Trained through</dt>
            <dd>{score.trained_through ?? '—'}</dd>
            <dt className="text-muted-foreground">Model version</dt>
            <dd>{score.model_version}</dd>
          </dl>
        )}
      </CardContent>
    </Card>
  )
}

type CveDetailProps = {
  item: QueueItem
  onBack: () => void
}

export function CveDetail({ item, onBack }: CveDetailProps) {
  const { cve_id, description, cvss_base_score } = item.vulnerability
  const fused = fusedScore(item)
  return (
    <div className="flex flex-col gap-4">
      <Button variant="outline" size="sm" className="self-start" onClick={onBack}>
        Back to queue
      </Button>

      <div>
        <h2 className="font-mono text-lg font-semibold">{cve_id}</h2>
        <p>{description}</p>
        <p className="text-muted-foreground">{affectedText(item)}</p>
        <p className="mt-2">
          CVSS {cvss_base_score?.toFixed(1) ?? '—'} · EPSS {item.epss?.toFixed(2) ?? '—'} ·
          Priority <strong>{fused === null ? 'not available' : toPercent(fused)}</strong>
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {sections.map(([component, title]) => (
          <ScoreSection key={component} title={title} score={findScore(item, component)} />
        ))}
      </div>
    </div>
  )
}
