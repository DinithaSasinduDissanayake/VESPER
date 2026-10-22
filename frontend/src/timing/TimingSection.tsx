// Owner: S.S.H. Thennakoon — the Exploit timing card on the CVE detail view.
// Real model output when the CVE is in the demo JSON, otherwise the sample card.
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { findScore } from '@/queue/format'
import { ScoreSection } from '@/queue/ScoreSection'
import type { QueueItem } from '@/queue/types'
import { REGENERATE_COMMAND, useTimingData } from './data'
import { RetrospectiveLabel, TimingDetailView } from './TimingDetail'

export function MissingDataCard({ message }: { message: string }) {
  return (
    <Card className="border-destructive/50">
      <CardHeader>
        <CardTitle>Exploit timing data is missing</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-2">
        <p className="text-muted-foreground">{message}</p>
        <p>
          Run: <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">{REGENERATE_COMMAND}</code>
        </p>
      </CardContent>
    </Card>
  )
}

export function TimingSection({ item }: { item: QueueItem }) {
  const state = useTimingData()
  const detail = state.status === 'ready' ? state.data.cves.current[item.vulnerability.cve_id] : undefined

  if (state.status === 'error') return <MissingDataCard message={state.message} />
  if (!detail) {
    return <ScoreSection title="Exploit timing · Sample data" score={findScore(item, 'b_survival')} />
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2">
          Exploit timing <RetrospectiveLabel />
        </CardTitle>
      </CardHeader>
      <CardContent>
        <TimingDetailView detail={detail} />
      </CardContent>
    </Card>
  )
}
