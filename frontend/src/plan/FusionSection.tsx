// Owner: B.L. Beminiwatte — extend this section here.
import { findScore } from '@/queue/format'
import { ScoreSection } from '@/queue/ScoreSection'
import type { QueueItem } from '@/queue/types'

export function FusionSection({ item }: { item: QueueItem }) {
  return <ScoreSection title="Fusion" score={findScore(item, 'd_fusion')} />
}
