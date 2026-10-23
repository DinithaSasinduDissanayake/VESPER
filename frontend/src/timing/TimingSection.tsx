// Owner: S.S.H. Thennakoon — the Exploit timing card on the CVE detail view.
// Real model output when the CVE is in the demo JSON. Otherwise nothing: the
// ranking's Exploit timing (B) card above already shows the real B score.
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import type { QueueItem } from '@/queue/types'
import { REGENERATE_COMMAND, useTimingData } from './data'
import { chanceText, day } from './format'
import { LevelBadge, Reasons, RetrospectiveLabel } from './TimingDetail'

export function MissingDataCard({ message }: { message: string }) {
  return (
    <Card className="border-destructive/50">
      <CardHeader>
        <CardTitle>Exploit timing data is missing</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-2">
        <p className="text-muted-foreground">{message}</p>
        <p>
          Run: <code className="rounded bg-muted px-1 py-0.5 font-mono text-sm">{REGENERATE_COMMAND}</code>
        </p>
      </CardContent>
    </Card>
  )
}

export function TimingSection({ item }: { item: QueueItem }) {
  const state = useTimingData()
  const detail = state.status === 'ready' ? state.data.cves.current[item.vulnerability.cve_id] : undefined

  if (state.status === 'error') return <MissingDataCard message={state.message} />
  if (!detail) return null
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2">
          Exploit timing <RetrospectiveLabel />
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <div className="flex items-center gap-3">
          <LevelBadge level={detail.level} status={detail.status} />
          {detail.raw_30d !== null && (
            <span>
              <strong className="text-lg">{chanceText(detail.raw_30d)}</strong>{' '}
              <span className="text-muted-foreground">estimated chance of joining CISA's attacked list (KEV) in 30 days</span>
            </span>
          )}
        </div>
        <Reasons detail={detail} />
        <p className="text-sm text-muted-foreground">As of {day(detail.decision_time)}.</p>
      </CardContent>
    </Card>
  )
}
