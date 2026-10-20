// Owner: S.S.H. Thennakoon — extend this section here.
// Later: survival curve and proof-of-concept timeline.
import { findScore } from '@/queue/format'
import { ScoreSection } from '@/queue/ScoreSection'
import type { QueueItem } from '@/queue/types'

export function TimingSection({ item }: { item: QueueItem }) {
  return <ScoreSection title="Exploit timing" score={findScore(item, 'b_survival')} />
}
