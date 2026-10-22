import { useEffect, useState } from 'react'
import {
  ArrowRight,
  CalendarClock,
  ChartNoAxesCombined,
  CircleAlert,
  Database,
  ShieldCheck,
} from 'lucide-react'
import { getPlannerRanking, type PlannerRanking } from '@/api/queue'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
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
        <Card className="border-blue-100/80 shadow-sm shadow-blue-950/[0.03] transition-all hover:-translate-y-0.5 hover:shadow-md dark:border-blue-900/60">
          <CardHeader className="flex flex-row items-start justify-between space-y-0 pb-2">
            <div>
              <CardDescription>Risk overview</CardDescription>
              <CardTitle className="mt-1 text-lg">Priority queue</CardTitle>
            </div>
            <span className="rounded-xl bg-blue-100 p-2.5 text-blue-800 dark:bg-blue-950 dark:text-blue-200"><ChartNoAxesCombined className="size-5" /></span>
          </CardHeader>
          <CardContent>
            <p className="text-sm leading-5 text-muted-foreground">Inspect the top 25 vulnerabilities and download the complete ranked list.</p>
            <button onClick={() => onNavigate('queue')} className="mt-4 inline-flex items-center gap-1 text-sm font-semibold text-primary hover:underline">
              Open ranking <ArrowRight className="size-4" />
            </button>
          </CardContent>
        </Card>
        <Card className="border-blue-100/80 shadow-sm shadow-blue-950/[0.03] transition-all hover:-translate-y-0.5 hover:shadow-md dark:border-blue-900/60">
          <CardHeader className="flex flex-row items-start justify-between space-y-0 pb-2">
            <div>
              <CardDescription>Capacity planning</CardDescription>
              <CardTitle className="mt-1 text-lg">Sprint plan</CardTitle>
            </div>
            <span className="rounded-xl bg-sky-100 p-2.5 text-sky-800 dark:bg-sky-950 dark:text-sky-200"><CalendarClock className="size-5" /></span>
          </CardHeader>
          <CardContent>
            <p className="text-sm leading-5 text-muted-foreground">Set team size, daily hours, and a planning period to optimize patch selection.</p>
            <button onClick={() => onNavigate('sprint')} className="mt-4 inline-flex items-center gap-1 text-sm font-semibold text-primary hover:underline">
              Plan patch work <ArrowRight className="size-4" />
            </button>
          </CardContent>
        </Card>
        <Card className="border-blue-100/80 shadow-sm shadow-blue-950/[0.03] transition-all hover:-translate-y-0.5 hover:shadow-md dark:border-blue-900/60">
          <CardHeader className="flex flex-row items-start justify-between space-y-0 pb-2">
            <div>
              <CardDescription>Decision support</CardDescription>
              <CardTitle className="mt-1 text-lg">Transparent signals</CardTitle>
            </div>
            <span className="rounded-xl bg-indigo-100 p-2.5 text-indigo-800 dark:bg-indigo-950 dark:text-indigo-200"><ShieldCheck className="size-5" /></span>
          </CardHeader>
          <CardContent>
            <p className="text-sm leading-5 text-muted-foreground">Review contributing evidence and keep risk ranking distinct from patch selection.</p>
            <button onClick={() => onNavigate('scores')} className="mt-4 inline-flex items-center gap-1 text-sm font-semibold text-primary hover:underline">
              How scores work <ArrowRight className="size-4" />
            </button>
          </CardContent>
        </Card>
      </section>

      <section className="grid gap-5 lg:grid-cols-[1.2fr_0.8fr]">
        <Card className="overflow-hidden border-blue-100/80 shadow-sm dark:border-blue-900/60">
          <CardHeader className="border-b bg-white/60 dark:bg-blue-950/20">
            <CardTitle className="text-base">Signal framework</CardTitle>
            <CardDescription>Five evidence streams inform the current provisional ranking.</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3 p-4 sm:grid-cols-2 lg:grid-cols-3">
            {signalDescriptions.map((signal) => (
              <div key={signal.key} className="rounded-xl border border-blue-100/80 bg-white/70 p-3 dark:border-blue-900/50 dark:bg-blue-950/20">
                <span className="mb-2 inline-flex min-w-10 justify-center rounded-md bg-blue-100 px-2 py-1 text-[11px] font-bold tracking-wide text-blue-800 dark:bg-blue-900/70 dark:text-blue-100">{signal.key}</span>
                <p className="text-sm font-semibold">{signal.title}</p>
                <p className="mt-1 text-xs leading-5 text-muted-foreground">{signal.detail}</p>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card className="overflow-hidden border-blue-100/80 shadow-sm dark:border-blue-900/60">
          <CardHeader className="border-b bg-white/60 dark:bg-blue-950/20">
            <CardTitle className="text-base">Highest current priorities</CardTitle>
            <CardDescription>Live from the configured ranking feed.</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            {topItems.length ? (
              <div className="divide-y divide-border">
                {topItems.map((item) => (
                  <div key={item.cve_id} className="flex items-center justify-between gap-4 px-4 py-3.5">
                    <div className="min-w-0">
                      <p className="truncate font-mono text-sm font-medium text-blue-800 dark:text-blue-200">{item.cve_id}</p>
                      <p className="mt-1 text-xs text-muted-foreground">Risk rank {item.model_rank}</p>
                    </div>
                    <span className="rounded-lg bg-blue-50 px-2.5 py-1.5 font-mono text-sm font-semibold text-blue-900 dark:bg-blue-950 dark:text-blue-100">
                      {item.risk_score.toFixed(3)}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="px-4 py-5 text-sm text-muted-foreground">
                {error ? 'Ranking feed unavailable.' : 'Loading current priorities…'}
              </p>
            )}
            <div className="border-t px-4 py-3">
              <button onClick={() => onNavigate('queue')} className="inline-flex items-center gap-1 text-sm font-semibold text-primary hover:underline">
                See full priority queue <ArrowRight className="size-4" />
              </button>
            </div>
          </CardContent>
        </Card>
      </section>
    </div>
  )
}
