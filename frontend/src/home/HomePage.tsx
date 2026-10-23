import { useEffect, useState } from 'react'
import {
  ArrowRight,
  CalendarClock,
  ChartNoAxesCombined,
  CircleAlert,
  Database,
  ShieldCheck,
  type LucideIcon,
} from 'lucide-react'
import { getPlannerRanking, type PlannerRanking } from '@/api/queue'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Separator } from '@/components/ui/separator'
import { cn } from '@/lib/utils'
import type { PageId } from '@/pages'

type HomePageProps = {
  onNavigate: (page: PageId) => void
}

const signalDescriptions = [
  { key: 'A', title: 'Text signal', detail: 'Risk evidence from vulnerability descriptions.' },
  { key: 'B', title: 'Exploit timing', detail: 'Exploit availability and timing evidence.' },
  { key: 'C', title: 'Structural relationships', detail: 'Graph based product and weakness context.' },
  { key: 'CVSS', title: 'Severity', detail: 'Published vulnerability severity score.' },
  { key: 'EPSS', title: 'Exploit likelihood', detail: 'Published exploitation probability estimate.' },
]

// The three cards under the heading; each opens a page.
const shortcuts: {
  page: PageId
  label: string
  title: string
  detail: string
  action: string
  icon: LucideIcon
}[] = [
  {
    page: 'queue',
    label: 'Risk overview',
    title: 'Priority queue',
    detail: 'Inspect the top 25 vulnerabilities and download the complete ranked list.',
    action: 'Open ranking',
    icon: ChartNoAxesCombined,
  },
  {
    page: 'sprint',
    label: 'Capacity planning',
    title: 'Sprint plan',
    detail: 'Set team size, daily hours, and a planning period to optimize patch selection.',
    action: 'Plan patch work',
    icon: CalendarClock,
  },
  {
    page: 'scores',
    label: 'Decision support',
    title: 'Transparent signals',
    detail: 'Review contributing evidence and keep risk ranking distinct from patch selection.',
    action: 'How scores work',
    icon: ShieldCheck,
  },
]

// Marker colour for each evidence stream (see --stream-* in index.css).
const streamDot: Record<string, string> = {
  A: 'bg-stream-text',
  B: 'bg-stream-timing',
  C: 'bg-stream-structure',
}

// Icon chip colour for the shortcut cards.
const shortcutChip: Record<PageId, string> = {
  home: 'bg-primary/10 text-primary',
  queue: 'bg-stream-ranking/10 text-stream-ranking',
  timing: 'bg-stream-timing/15 text-stream-timing',
  exposure: 'bg-stream-structure/10 text-stream-structure',
  sprint: 'bg-stream-ranking/10 text-stream-ranking',
  analyse: 'bg-stream-text/10 text-stream-text',
  scores: 'bg-primary/10 text-primary',
}

export function HomePage({ onNavigate }: HomePageProps) {
  const [ranking, setRanking] = useState<PlannerRanking | null>(null)
  const [error, setError] = useState(false)

  useEffect(() => {
    const controller = new AbortController()
    getPlannerRanking(controller.signal)
      .then(setRanking)
      .catch(() => {
        if (!controller.signal.aborted) setError(true)
      })
    return () => controller.abort()
  }, [])

  const topItems = ranking?.vulnerabilities.slice(0, 3) ?? []

  return (
    <div className="mx-auto max-w-7xl space-y-7">
      <section className="relative isolate overflow-hidden rounded-3xl bg-gradient-to-br from-[#071b39] via-[#0b3977] to-[#1269a8] px-6 py-8 text-white shadow-xl shadow-blue-950/15 md:px-10 md:py-11">
        <div aria-hidden="true" className="pointer-events-none absolute -right-24 -top-36 -z-10 size-[30rem] rounded-full border border-white/10" />
        <div aria-hidden="true" className="pointer-events-none absolute -right-8 -top-20 -z-10 size-[22rem] rounded-full border border-white/10" />
        <div aria-hidden="true" className="pointer-events-none absolute right-24 top-10 -z-10 size-48 rounded-full bg-cyan-300/10 blur-3xl" />
        <div className="relative grid gap-8 md:grid-cols-[1.35fr_0.65fr] md:items-end">
          <div>
            <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-white/15 bg-white/10 px-3 py-1.5 text-xs font-medium text-blue-100 backdrop-blur">
              <ShieldCheck className="size-4 text-cyan-200" />
              Evidence led vulnerability prioritization
            </div>
            <h2 className="max-w-2xl text-3xl font-semibold leading-tight tracking-tight md:text-5xl">
              Turn vulnerability signals into a patch plan.
            </h2>
            <p className="mt-4 max-w-2xl text-sm leading-6 text-blue-100/85 md:text-base">
              Review the current risk ranking, then allocate team capacity to build a practical daily, weekly, or monthly patch schedule.
            </p>
            <div className="mt-7 flex flex-wrap gap-3">
              <Button onClick={() => onNavigate('queue')} className="h-10 bg-white px-4 font-semibold text-blue-950 shadow-md hover:bg-blue-50">
                View priority queue <ArrowRight />
              </Button>
              <Button onClick={() => onNavigate('sprint')} variant="outline" className="h-10 border-white/30 bg-white/10 px-4 text-white hover:bg-white/15 hover:text-white">
                Build a patch plan <CalendarClock />
              </Button>
            </div>
          </div>

          <div className="rounded-2xl border border-white/15 bg-white/10 p-5 shadow-inner backdrop-blur-md">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-sm font-medium text-blue-50">
                <Database className="size-4 text-cyan-200" />
                Current ranking feed
              </div>
              <span className="rounded-full border border-amber-200/25 bg-amber-300/15 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider text-amber-100">
                Provisional
              </span>
            </div>
            <div className="mt-6 flex items-end gap-3">
              <span className="text-4xl font-semibold tabular-nums tracking-tight">
                {ranking ? ranking.count.toLocaleString() : '—'}
              </span>
              <span className="pb-1 text-sm text-blue-100/75">ranked CVEs</span>
            </div>
            <p className="mt-2 text-xs leading-5 text-blue-100/70">
              {ranking
                ? `Composite ranking${ranking.vulnerabilities[0]?.data_as_of ? ` · data as of ${ranking.vulnerabilities[0].data_as_of}` : ''}`
                : error
                  ? 'Ranking feed unavailable. Start the API and verify the ranking file.'
                  : 'Checking ranking feed…'}
            </p>
            <div className="mt-5 h-px bg-white/15" />
            <p className="mt-4 flex items-start gap-2 text-xs leading-5 text-blue-100/75">
              <CircleAlert className="mt-0.5 size-4 shrink-0 text-amber-200" />
              This is an equal-weight provisional composite, not a trained or validated predictive model.
            </p>
          </div>
        </div>
      </section>

      <section className="grid gap-4 sm:grid-cols-3">
        {shortcuts.map(({ page, label, title, detail, action, icon: Icon }) => (
          <Card key={page}>
            <CardHeader>
              <CardDescription>{label}</CardDescription>
              <CardTitle>{title}</CardTitle>
              <CardAction>
                <span className={cn('grid size-9 place-items-center rounded-lg', shortcutChip[page])}>
                  <Icon className="size-4" />
                </span>
              </CardAction>
            </CardHeader>
            <CardContent className="flex-1">
              <p className="text-base text-muted-foreground">{detail}</p>
            </CardContent>
            <CardFooter>
              <Button variant="outline" onClick={() => onNavigate(page)}>
                {action} <ArrowRight data-icon="inline-end" />
              </Button>
            </CardFooter>
          </Card>
        ))}
      </section>

      <section className="grid gap-4 lg:grid-cols-[1.2fr_0.8fr]">
        <Card>
          <CardHeader>
            <CardTitle>Signal framework</CardTitle>
            <CardDescription>Five evidence streams inform the current provisional ranking.</CardDescription>
          </CardHeader>
          <CardContent>
            <dl className="grid gap-x-6 gap-y-4 text-base sm:grid-cols-2">
              {signalDescriptions.map((signal) => (
                <div key={signal.key} className="flex items-start gap-3">
                  <Badge variant="secondary" className="mt-px w-16">
                    <span className={cn('size-1.5 shrink-0 rounded-full', streamDot[signal.key] ?? 'bg-muted-foreground/60')} />
                    {signal.key}
                  </Badge>
                  <div className="flex flex-col gap-0.5">
                    <dt className="font-medium">{signal.title}</dt>
                    <dd className="text-muted-foreground">{signal.detail}</dd>
                  </div>
                </div>
              ))}
            </dl>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Highest current priorities</CardTitle>
            <CardDescription>Live from the configured ranking feed.</CardDescription>
          </CardHeader>
          <CardContent className="flex-1">
            {topItems.length ? (
              <ul className="flex flex-col text-base">
                {topItems.map((item, index) => (
                  <li key={item.cve_id} className="flex flex-col">
                    {index > 0 && <Separator />}
                    <div className="flex items-center justify-between gap-4 py-3">
                      <div className="flex min-w-0 flex-col gap-0.5">
                        <span className="truncate font-mono font-medium">{item.cve_id}</span>
                        <span className="text-sm text-muted-foreground">Risk rank {item.model_rank}</span>
                      </div>
                      <div className="flex w-28 shrink-0 flex-col items-end gap-1.5">
                        <span className="font-medium tabular-nums">{item.risk_score.toFixed(3)}</span>
                        <Progress value={item.risk_score * 100} aria-label={`Risk score ${item.risk_score.toFixed(3)}`} />
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="flex flex-col items-center gap-3 py-8 text-center text-muted-foreground">
                <span className="grid size-10 place-items-center rounded-full bg-muted">
                  <Database className="size-5" />
                </span>
                <p className="text-base">
                  {error ? 'Ranking feed unavailable.' : 'Loading current priorities…'}
                </p>
              </div>
            )}
          </CardContent>
          <CardFooter>
            <Button variant="outline" onClick={() => onNavigate('queue')}>
              See full priority queue <ArrowRight data-icon="inline-end" />
            </Button>
          </CardFooter>
        </Card>
      </section>
    </div>
  )
}
