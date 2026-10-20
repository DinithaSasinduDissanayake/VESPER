import { useEffect, useState } from 'react'
import { getQueue } from './queue'
import type { QueueItem } from '@/queue/types'

// Loads the queue once. Returns null while it is still loading.
export function useQueue(): QueueItem[] | null {
  const [items, setItems] = useState<QueueItem[] | null>(null)
  useEffect(() => {
    getQueue().then(setItems)
  }, [])
  return items
}
