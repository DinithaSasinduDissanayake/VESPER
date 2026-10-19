// Owner: D.S. Dissanayake — extend this section here.
import { findScore } from '@/queue/format'
import { ScoreSection } from '@/queue/ScoreSection'
import type { QueueItem } from '@/queue/types'

export function TextSection({ item }: { item: QueueItem }) {
  return <ScoreSection title="Text signal" score={findScore(item, 'a_text')} />
}
