import { sampleQueue } from '@/queue/sampleQueue'
import type { QueueItem } from '@/queue/types'

// The one place where pages get queue data.
// Today it returns the sample data. Later it becomes a backend call, e.g.
//   const response = await fetch('/api/queue')
//   return (await response.json()) as QueueItem[]
// The response must match the contract types in queue/types.ts.
export async function getQueue(): Promise<QueueItem[]> {
  return sampleQueue
}
