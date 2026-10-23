import { useEffect, useState } from 'react'
import { ArrowRight, CircleAlert, Database } from 'lucide-react'
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
import { pages, type PageId } from '@/pages'

type HomePageProps = {
  onNavigate: (page: PageId) => void
  onOpenCve: (cveId: string) => void
}

// Quick actions card: one button per function of the app.
const quickActions: { page: PageId; label: string }[] = [
  { page: 'queue', label: 'Priority queue' },
  { page: 'sprint', label: 'Sprint plan' },
  { page: 'analyse', label: 'Analyse a new CVE (A)' },
  { page: 'timing', label: 'Exploit timing (B)' },
  { page: 'exposure', label: 'Structural relationships (C)' },
  { page: 'queue', label: 'CVE detail (open one from the queue)' },
]

export function HomePage({ onNavigate, onOpenCve }: HomePageProps) {
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
      <section className="grid gap-4 lg:grid-cols-2">
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
                    <button
                      type="button"
                      onClick={() => onOpenCve(item.cve_id)}
                      aria-label={`Open details for ${item.cve_id}`}
                      className="-mx-2 flex items-center justify-between gap-4 rounded-md px-2 py-3 text-left outline-none transition-colors hover:bg-muted/60 focus-visible:ring-3 focus-visible:ring-ring/50"
                    >
                      <div className="flex min-w-0 flex-col gap-0.5">
                        <span className="truncate font-mono font-medium">{item.cve_id}</span>
                        <span className="text-sm text-muted-foreground">Risk rank {item.model_rank}</span>
                      </div>
                      <div className="flex w-28 shrink-0 flex-col items-end gap-1.5">
                        <span className="font-medium tabular-nums">{item.risk_score.toFixed(3)}</span>
                        <Progress value={item.risk_score * 100} aria-label={`Risk score ${item.risk_score.toFixed(3)}`} />
                      </div>
                    </button>
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

      <Card>
        <CardHeader>
          <CardTitle>Quick actions</CardTitle>
          <CardDescription>Jump straight to any part of VESPER.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          {quickActions.map(({ page, label }) => {
            const Icon = pages[page].icon
            return (
              <Button key={label} variant="outline" onClick={() => onNavigate(page)}>
                {Icon && <Icon data-icon="inline-start" />}
                {label}
              </Button>
            )
          })}
        </CardContent>
      </Card>
    </div>
  )
}
