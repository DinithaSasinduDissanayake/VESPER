// Owner: H.T.D. Fernando — extend this section here.
import { findScore } from '@/queue/format'
import { ScoreSection } from '@/queue/ScoreSection'
import type { QueueItem } from '@/queue/types'

export function ExposureSection({ item }: { item: QueueItem }) {
  return <ScoreSection title="Exposure" score={findScore(item, 'c_graph')} />
}
