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
import { Separator } from '@/components/ui/separator'
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
    <div className="mx-auto flex max-w-6xl flex-col gap-6">
      <section className="grid gap-6 py-2 lg:grid-cols-[minmax(0,1fr)_22rem] lg:items-end">
        <div className="flex flex-col items-start gap-4">
          <Badge variant="outline">
            <ShieldCheck data-icon="inline-start" />
            Evidence led vulnerability prioritization
          </Badge>
          <h2 className="max-w-2xl text-3xl font-semibold tracking-tight text-balance md:text-4xl">
            Turn vulnerability signals into a patch plan.
          </h2>
          <p className="max-w-2xl text-lg text-pretty text-muted-foreground">
            Review the current risk ranking, then allocate team capacity to build a practical daily, weekly, or monthly patch schedule.
          </p>
          <div className="flex flex-wrap gap-2">
            <Button size="lg" onClick={() => onNavigate('queue')}>
              View priority queue <ArrowRight data-icon="inline-end" />
            </Button>
            <Button size="lg" variant="outline" onClick={() => onNavigate('sprint')}>
              Build a patch plan <CalendarClock data-icon="inline-end" />
            </Button>
          </div>
        </div>

        <Card>
          <CardHeader>
            <CardDescription className="flex items-center gap-2">
              <Database className="size-4" />
              Current ranking feed
            </CardDescription>
            <CardAction>
              <Badge variant="outline">Provisional</Badge>
            </CardAction>
            <CardTitle className="flex items-baseline gap-2">
              <span className="text-3xl font-semibold tabular-nums tracking-tight">
                {ranking ? ranking.count.toLocaleString() : '—'}
              </span>
              <span className="text-sm font-normal text-muted-foreground">ranked CVEs</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-3 text-muted-foreground">
            <p>
              {ranking
                ? `Composite ranking${ranking.vulnerabilities[0]?.data_as_of ? ` · data as of ${ranking.vulnerabilities[0].data_as_of}` : ''}`
                : error
                  ? 'Ranking feed unavailable. Start the API and verify the ranking file.'
                  : 'Checking ranking feed…'}
            </p>
            <Separator />
            <p className="flex items-start gap-2">
              <CircleAlert className="mt-0.5 size-4 shrink-0" />
              This is an equal-weight provisional composite, not a trained or validated predictive model.
            </p>
          </CardContent>
        </Card>
      </section>

      <section className="grid gap-4 sm:grid-cols-3">
        {shortcuts.map(({ page, label, title, detail, action, icon: Icon }) => (
          <Card key={page}>
            <CardHeader>
              <CardDescription>{label}</CardDescription>
              <CardTitle>{title}</CardTitle>
              <CardAction>
                <span className="grid size-8 place-items-center rounded-lg bg-muted text-muted-foreground">
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
                  <Badge variant="secondary" className="mt-px w-12">{signal.key}</Badge>
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
                      <span className="font-medium tabular-nums">{item.risk_score.toFixed(3)}</span>
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="py-3 text-base text-muted-foreground">
                {error ? 'Ranking feed unavailable.' : 'Loading current priorities…'}
              </p>
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
