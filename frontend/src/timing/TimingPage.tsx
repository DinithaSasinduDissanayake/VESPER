// Owner: S.S.H. Thennakoon — Exploit timing page: an urgent list for the people
// who patch, and a separate tab with the proof (real model output).
import { Fragment, useState } from 'react'
import { ExternalLink, ShieldAlert } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { cn } from '@/lib/utils'
import { BandsChart, LineChart } from './charts'
import { useTimingData } from './data'
import { bandLabel, chanceText, day, whatItIs, zoomedDomain } from './format'
import { LevelBadge, Reasons, RetrospectiveLabel } from './TimingDetail'
import { MissingDataCard } from './TimingSection'
import type { Interval, TimingData } from './types'

const cohortNames: Record<string, string> = { post_kev: 'CVEs since KEV began (main)', full: 'All CVEs' }

function ci([lower, upper]: Interval, digits = 3): string {
  return `${lower.toFixed(digits)} to ${upper.toFixed(digits)}`
}

function signed(value: number, digits = 3): string {
  return `${value >= 0 ? '+' : ''}${value.toFixed(digits)}`
}

// ---------------------------------------------------------------------------
// Tab 1: Urgent list
// ---------------------------------------------------------------------------

function UrgentTable({ data }: { data: TimingData }) {
  const [openId, setOpenId] = useState<string | null>(null)
  return (
    <Card className="min-w-0">
      <CardHeader>
        <CardTitle>Patch these first</CardTitle>
        <CardDescription>
          The {data.top.length} vulnerabilities most likely to be added to CISA's list of attacked vulnerabilities
          (KEV) in the next 30 days. Click a row to see why.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-12 text-right">#</TableHead>
              <TableHead>Level</TableHead>
              <TableHead>Vulnerability</TableHead>
              <TableHead>Software</TableHead>
              <TableHead>Published</TableHead>
              <TableHead className="text-right">30-day chance</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.top.map((id) => {
              const detail = data.cves.current[id]
              const open = openId === id
              return (
                <Fragment key={id}>
                  <TableRow
                    className={cn('cursor-pointer', open && 'bg-muted/50')}
                    onClick={() => setOpenId(open ? null : id)}
                    aria-expanded={open}
                  >
                    <TableCell className="text-right">{detail.rank ?? '—'}</TableCell>
                    <TableCell>
                      <LevelBadge level={detail.level} status={detail.status} />
                    </TableCell>
                    <TableCell className="font-mono">{id}</TableCell>
                    <TableCell className="max-w-64 truncate" title={whatItIs(detail)}>
                      {whatItIs(detail)}
                    </TableCell>
                    <TableCell>{detail.published}</TableCell>
                    <TableCell className="text-right font-medium">{chanceText(detail.raw_30d)}</TableCell>
                  </TableRow>
                  {open && (
                    <TableRow className="bg-muted/30 hover:bg-muted/30">
                      <TableCell />
                      <TableCell colSpan={5} className="whitespace-normal">
                        <div className="flex flex-col gap-2 py-1">
                          <Reasons detail={detail} />
                          <a
                            href={detail.nvd_url}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-1 self-start text-xs underline"
                          >
                            Read the full advisory on NVD <ExternalLink className="size-3" />
                          </a>
                        </div>
                      </TableCell>
                    </TableRow>
                  )}
                </Fragment>
              )
            })}
          </TableBody>
        </Table>
        <p className="mt-2 text-xs text-muted-foreground">
          Vulnerabilities with the same score share the same number.
        </p>
      </CardContent>
    </Card>
  )
}

function AlreadyAttacked({ data }: { data: TimingData }) {
  const { recent_kev: recent } = data
  return (
    <Card className="border-red-500/40">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldAlert className="size-4 text-red-600" /> Already attacked: patch these first
        </CardTitle>
        <CardDescription>
          {recent.count} vulnerabilities were added to the KEV list in the {recent.window_days} days before{' '}
          {day(data.meta.decision_time)}. They are known to be attacked, so there is nothing to predict.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ul className="flex flex-col gap-2">
          {recent.items.map((item) => (
            <li key={item.cve_id} className="flex flex-col">
              <a href={item.nvd_url} target="_blank" rel="noreferrer" className="font-mono underline">
                {item.cve_id}
              </a>
              <span>{[item.vendor, item.product].filter(Boolean).join(' ') || item.name}</span>
              <span className="text-xs text-muted-foreground">Added {item.date_added}</span>
            </li>
          ))}
        </ul>
        {recent.count > recent.items.length && (
          <p className="mt-2 text-xs text-muted-foreground">
            Showing the newest {recent.items.length} of {recent.count}.
          </p>
        )}
      </CardContent>
    </Card>
  )
}

function UrgentTab({ data }: { data: TimingData }) {
  return (
    <div className="flex flex-col gap-4">
      <p className="text-muted-foreground">
        As of <strong className="text-foreground">{day(data.meta.decision_time)}</strong>. Levels:{' '}
        <strong className="text-foreground">High</strong> = top 5% of all scored vulnerabilities (
        {data.levels.counts.High.toLocaleString()}), <strong className="text-foreground">Medium</strong> = next 15%,{' '}
        <strong className="text-foreground">Low</strong> = the rest. The 30-day chance is an estimate for ranking.
      </p>
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1fr_20rem]">
        <UrgentTable data={data} />
        <AlreadyAttacked data={data} />
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Tab 2: How good is it?
// ---------------------------------------------------------------------------

function BigResult({ data }: { data: TimingData }) {
  const { cox, cvss, difference } = data.results.main.post_kev
  return (
    <Card className={cn(difference.excludes_zero ? 'border-emerald-500/50' : 'border-border')}>
      <CardHeader>
        <CardDescription>Tested on past data that the model never saw</CardDescription>
        <CardTitle className="text-xl leading-snug">
          {difference.excludes_zero
            ? 'Our ranking puts attacked vulnerabilities higher than CVSS does, and the difference is significant.'
            : 'Our ranking is not significantly better than CVSS.'}
        </CardTitle>
      </CardHeader>
      <CardContent className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div>
          <p className="text-muted-foreground">Our model (C-index)</p>
          <p className="text-2xl font-semibold">{cox.c_index.toFixed(3)}</p>
          <p className="text-xs text-muted-foreground">95% CI {ci(cox.c_index_ci)}</p>
        </div>
        <div>
          <p className="text-muted-foreground">CVSS alone (C-index)</p>
          <p className="text-2xl font-semibold">{cvss.c_index.toFixed(3)}</p>
          <p className="text-xs text-muted-foreground">95% CI {ci(cvss.c_index_ci)}</p>
        </div>
        <div>
          <p className="text-muted-foreground">Difference</p>
          <p className="text-2xl font-semibold">{signed(difference.difference)}</p>
          <p className="text-xs text-muted-foreground">
            95% CI {ci(difference.ci)} ({difference.excludes_zero ? 'excludes 0' : 'includes 0'})
          </p>
        </div>
        <p className="text-xs text-muted-foreground sm:col-span-3">
          C-index = how often the model puts the vulnerability that was attacked first above another one (0.5 =
          guessing, 1 = perfect). Trained on data before {data.results.main_cutoff} ({cox.train_events} KEV
          listings), tested on the next 365 days ({cox.test_events} listings), same 1,000 resamples for both.
        </p>
      </CardContent>
    </Card>
  )
}

function DifferenceTable({ data }: { data: TimingData }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Every test date, including where it is not better</CardTitle>
        <CardDescription>Our model minus CVSS. Greyed rows are not significant.</CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Group</TableHead>
              <TableHead>Trained up to</TableHead>
              <TableHead className="text-right">Training listings</TableHead>
              <TableHead className="text-right">Difference</TableHead>
              <TableHead>95% CI</TableHead>
              <TableHead>Result</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.results.differences.map((row) => (
              <TableRow
                key={`${row.cohort}-${row.cutoff}`}
                className={cn(
                  !row.excludes_zero && 'text-muted-foreground',
                  row.cutoff === data.results.main_cutoff && row.cohort === 'post_kev' && 'font-semibold',
                )}
              >
                <TableCell>{cohortNames[row.cohort] ?? row.cohort}</TableCell>
                <TableCell>{row.cutoff}</TableCell>
                <TableCell className="text-right">
                  {row.train_events}
                  {row.train_events < 100 && ' (too few)'}
                </TableCell>
                <TableCell className="text-right">{signed(row.difference)}</TableCell>
                <TableCell>{ci(row.ci)}</TableCell>
                <TableCell>{row.excludes_zero ? 'significant' : 'not significant'}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}

function Backtest({ data }: { data: TimingData }) {
  const summary = data.backtest
  return (
    <Card>
      <CardHeader>
        <CardTitle>A real month: September 2026</CardTitle>
        <CardDescription>
          The model was trained only on data before {day(summary.decision_time)}. In the next {summary.window_days}{' '}
          days, {summary.listed} vulnerabilities were added to KEV. {summary.listed_published_after_decision} of them
          did not exist yet on that date; the other {summary.scored} were ranked among{' '}
          {summary.available_population.toLocaleString()}.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-2">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Of the {summary.scored}, how many were in the…</TableHead>
              <TableHead className="text-right">Our model</TableHead>
              <TableHead className="text-right">CVSS</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {Object.entries(summary.top_counts).map(([name, counts]) => (
              <TableRow key={name}>
                <TableCell>top {name.replace('top_', '').replace('pct', '%')}</TableCell>
                <TableCell className="text-right font-medium">{counts.b}</TableCell>
                <TableCell className="text-right font-medium">{counts.cvss}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        <p className="text-xs text-muted-foreground">
          {summary.rank_note} One month and {summary.scored} vulnerabilities: an example, not proof.
        </p>
      </CardContent>
    </Card>
  )
}

function Curves({ data }: { data: TimingData }) {
  const { kaplan_meier: km, bands } = data.results
  const [first, second] = bands
  const last = bands[bands.length - 1]
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>When the risk is highest</CardTitle>
          <CardDescription>Risk of being added to KEV by age (per 100,000 vulnerabilities per day)</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          <BandsChart bands={bands} />
          <p>
            The first 30 days carry about <strong>{(first.rate_per_day / second.rate_per_day).toFixed(0)}×</strong>{' '}
            the risk of days 30–90, and about <strong>{(first.rate_per_day / last.rate_per_day).toFixed(0)}×</strong>{' '}
            the risk after {bandLabel(last)}.
          </p>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>How many are ever listed</CardTitle>
          <CardDescription>
            {km.rows.toLocaleString()} vulnerabilities since KEV began; {km.events.toLocaleString()} were listed
          </CardDescription>
        </CardHeader>
        <CardContent>
          <LineChart
            points={km.points}
            title="Share of vulnerabilities not yet in KEV, by days since publication"
            xLabel="Days since publication"
            yLabel="Not yet in KEV"
            yDomain={zoomedDomain(km.points.map(([, value]) => value))}
            formatY={(value) => `${(value * 100).toFixed(2)}%`}
            zoomNote="Zoomed axis: it does not start at 0. Fewer than 1 in 100 are ever listed."
          />
        </CardContent>
      </Card>
    </div>
  )
}

function HazardRatios({ data }: { data: TimingData }) {
  const rows = data.results.hazard_ratios.filter((row) => row.p_value < 0.05)
  return (
    <Card>
      <CardHeader>
        <CardTitle>What makes a vulnerability more urgent</CardTitle>
        <CardDescription>
          Effects the model found with confidence (p &lt; 0.05). Above 1 = listed sooner, below 1 = later.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Factor</TableHead>
              <TableHead className="text-right">Effect on risk</TableHead>
              <TableHead>95% CI</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((row) => (
              <TableRow key={row.feature}>
                <TableCell>{row.label}</TableCell>
                <TableCell className="text-right font-medium">× {row.hazard_ratio.toFixed(2)}</TableCell>
                <TableCell>{ci(row.ci, 2)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}

function Limitations({ data }: { data: TimingData }) {
  const { cox, cvss } = data.results.main.post_kev
  return (
    <Card className="border-amber-500/40">
      <CardHeader>
        <CardTitle>Limitations</CardTitle>
      </CardHeader>
      <CardContent>
        <ul className="flex list-disc flex-col gap-1 pl-5">
          <li>{data.meta.note}</li>
          <li>
            The whole ranking is better than CVSS, but the very top is not: of the top 100, {cox.p_at_100.toFixed(2)}{' '}
            were listed, against {cvss.p_at_100.toFixed(2)} for CVSS.
          </li>
          <li>The earliest test dates (2022–2023) had fewer than 100 KEV listings to learn from.</li>
          <li>The 30-day chance is a ranking estimate; it has not been checked as a true probability.</li>
          <li>Being added to KEV is not the first attack; it is the first public, dated record of one.</li>
        </ul>
      </CardContent>
    </Card>
  )
}

function ProofTab({ data }: { data: TimingData }) {
  return (
    <div className="flex flex-col gap-4">
      <BigResult data={data} />
      <DifferenceTable data={data} />
      <Backtest data={data} />
      <Curves data={data} />
      <HazardRatios data={data} />
      <Limitations data={data} />
      <p className="text-xs text-muted-foreground">
        Model {data.meta.model_version} · data snapshot {data.meta.snapshot_date} · generated{' '}
        {day(data.meta.generated_at)}
      </p>
    </div>
  )
}

export function TimingPage() {
  const state = useTimingData()
  if (state.status === 'loading') return <p className="text-muted-foreground">Loading exploit timing…</p>
  if (state.status === 'error') return <MissingDataCard message={state.message} />
  const { data } = state

  return (
    <Tabs defaultValue="urgent" className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <TabsList>
          <TabsTrigger value="urgent">Urgent list</TabsTrigger>
          <TabsTrigger value="proof">How good is it?</TabsTrigger>
        </TabsList>
        <RetrospectiveLabel />
      </div>
      <TabsContent value="urgent">
        <UrgentTab data={data} />
      </TabsContent>
      <TabsContent value="proof">
        <ProofTab data={data} />
      </TabsContent>
    </Tabs>
  )
}
