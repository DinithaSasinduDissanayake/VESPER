import { useState } from 'react'
import { useQueue } from '@/api/useQueue'
import { CveDetail } from './CveDetail'
import { PriorityQueue } from './PriorityQueue'

// The queue list, or the detail view of one CVE.
export function QueuePage() {
  const items = useQueue()
  // The CVE open in the detail view, or null to show the list.
  const [selectedCveId, setSelectedCveId] = useState<string | null>(null)
  if (!items) return <p>Loading…</p>

  const selectedItem = items.find((item) => item.vulnerability.cve_id === selectedCveId)
  return (
    <>
      <p className="mb-4 text-muted-foreground">Sample data — not real model output.</p>
      {selectedItem ? (
        <CveDetail item={selectedItem} onBack={() => setSelectedCveId(null)} />
      ) : (
        <PriorityQueue items={items} onSelect={setSelectedCveId} />
      )}
    </>
  )
}
