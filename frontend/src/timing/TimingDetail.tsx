// Small building blocks for the plain-language Exploit timing views.
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import type { ScoreStatus } from '@/queue/types'
import type { Level, TimingDetail } from './types'

export function RetrospectiveLabel({ text = 'Real model output (retrospective)' }: { text?: string }) {
  return (
    <span className="rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-xs font-medium text-amber-800 dark:text-amber-300">
      {text}
    </span>
  )
}

const levelStyles: Record<Level, string> = {
  High: 'bg-red-600 text-white dark:bg-red-500',
  Medium: 'bg-amber-500 text-black',
  Low: 'bg-emerald-600 text-white dark:bg-emerald-500',
}

export function LevelBadge({ level, status }: { level: Level | null; status?: ScoreStatus }) {
  if (status === 'already_exploited') return <Badge className="bg-red-900 text-white">Already attacked</Badge>
  if (!level) return <Badge variant="outline">No score</Badge>
  return <Badge className={cn('min-w-16 justify-center', levelStyles[level])}>{level}</Badge>
}

export function Reasons({ detail }: { detail: TimingDetail }) {
  return (
    <ul className="flex list-disc flex-col gap-1 pl-5">
      {detail.reasons.map((reason) => (
        <li key={reason}>{reason}</li>
      ))}
    </ul>
  )
}
