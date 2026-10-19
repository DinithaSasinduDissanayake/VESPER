import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { statusLabels, toPercent } from './format'
import type { Score } from './types'

// Shared card for one evidence section: the full Score, or a placeholder
// when there is no number. Each owner's section file uses it.
export function ScoreSection({ title, score }: { title: string; score: Score | undefined }) {
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
