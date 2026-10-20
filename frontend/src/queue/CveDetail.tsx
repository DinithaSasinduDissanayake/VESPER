import { Button } from '@/components/ui/button'
import { TextSection } from '@/analyse/TextSection'
import { ExposureSection } from '@/exposure/ExposureSection'
import { FusionSection } from '@/plan/FusionSection'
import { TimingSection } from '@/timing/TimingSection'
import { affectedText, fusedScore, toPercent } from './format'
import type { QueueItem } from './types'

type CveDetailProps = {
  item: QueueItem
  onBack: () => void
}

export function CveDetail({ item, onBack }: CveDetailProps) {
  const { cve_id, description, cvss_base_score } = item.vulnerability
  const fused = fusedScore(item)
  return (
    <div className="flex flex-col gap-4">
      <Button variant="outline" size="sm" className="self-start" onClick={onBack}>
        Back to queue
      </Button>

      <div>
        <h2 className="font-mono text-lg font-semibold">{cve_id}</h2>
        <p>{description}</p>
        <p className="text-muted-foreground">{affectedText(item)}</p>
        <p className="mt-2">
          CVSS {cvss_base_score?.toFixed(1) ?? '—'} · EPSS {item.epss?.toFixed(2) ?? '—'} ·
          Priority <strong>{fused === null ? 'not available' : toPercent(fused)}</strong>
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <TextSection item={item} />
        <TimingSection item={item} />
        <ExposureSection item={item} />
        <FusionSection item={item} />
      </div>
    </div>
  )
}
