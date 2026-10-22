// Owner: S.S.H. Thennakoon — Exploit timing results page (real model output).
import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { statusLabels } from '@/queue/format'
import { cn } from '@/lib/utils'
import { BandsChart, LineChart } from './charts'
import { useTimingData } from './data'
import { MissingDataCard } from './TimingSection'
import { bandLabel, day, zoomedDomain } from './format'
import { RetrospectiveLabel, TimingDetailView } from './TimingDetail'
import type { Difference, Interval, TimingData, TimingDetail } from './types'

const cohortNames: Record<string, string> = { post_kev: 'Post-KEV (main)', full: 'All CVEs' }

function ci([lower, upper]: Interval, digits = 3): string {
  return `${lower.toFixed(digits)} to ${upper.toFixed(digits)}`
}

function signed(value: number, digits = 3): string {
  return `${value >= 0 ? '+' : ''}${value.toFixed(digits)}`
}

function Verdict({ difference }: { difference: Difference }) {
  return difference.excludes_zero ? (
    <span className="font-medium text-emerald-700 dark:text-emerald-400">significant (interval excludes 0)</span>
  ) : (
    <span className="font-medium text-muted-foreground">not significant (interval includes 0)</span>
  )
}

function Headline({ data }: { data: TimingData }) {
  const { main, main_cutoff } = data.results
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      {(['post_kev', 'full'] as const).map((cohort) => {
        const { cox, cvss, difference } = main[cohort]
        return (
          <Card key={cohort}>
            <CardHeader>
              <CardTitle>{cohortNames[cohort]}</CardTitle>
              <CardDescription>
                Cut-off {main_cutoff}: trained on {cox.train_events} KEV listings, tested on the next 365 days (
                {cox.test_events} listings)
              </CardDescription>
            </CardHeader>
            <CardContent>
              <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
                <dt className="text-muted-foreground">C-index, survival model</dt>
                <dd className="font-semibold">
                  {cox.c_index.toFixed(3)} <span className="font-normal">({ci(cox.c_index_ci)})</span>
                </dd>
                <dt className="text-muted-foreground">C-index, CVSS only</dt>
                <dd className="font-semibold">
                  {cvss.c_index.toFixed(3)} <span className="font-normal">({ci(cvss.c_index_ci)})</span>
                </dd>
                <dt className="text-muted-foreground">Paired difference</dt>
                <dd>
                  <span className="text-lg font-semibold">{signed(difference.difference)}</span> (95% CI{' '}
                  {ci(difference.ci)})
                  <br />
                  <Verdict difference={difference} />
                </dd>
                <dt className="text-muted-foreground">P@100 model / CVSS</dt>
                <dd>
                  {cox.p_at_100.toFixed(2)} / {cvss.p_at_100.toFixed(2)}
                </dd>
              </dl>
            </CardContent>
          </Card>
        )
      })}
    </div>
  )
}

function DifferenceTable({ data }: { data: TimingData }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>C-index difference at every cut-off</CardTitle>
        <CardDescription>
          Survival model minus CVSS, on the same 1,000 bootstrap resamples. Every cut-off is shown, including the ones
          where the model is not better.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Cohort</TableHead>
              <TableHead>Cut-off</TableHead>
              <TableHead className="text-right">Train listings</TableHead>
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

function Curves({ data }: { data: TimingData }) {
  const { kaplan_meier: km, bands } = data.results
  const first = bands[0]
  const later = bands[bands.length - 1]
  const ratio = first.rate_per_day / later.rate_per_day
  const second = bands[1]
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Time to KEV listing (Kaplan–Meier)</CardTitle>
          <CardDescription>
            Post-KEV CVEs: {km.rows.toLocaleString()} CVEs, {km.events.toLocaleString()} listed in KEV
          </CardDescription>
        </CardHeader>
        <CardContent>
          <LineChart
            points={km.points}
            title="Share of CVEs not yet in KEV by days since publication"
            xLabel="Days since publication"
            yLabel="Not yet in KEV"
            yDomain={zoomedDomain(km.points.map(([, value]) => value))}
            formatY={(value) => `${(value * 100).toFixed(2)}%`}
            zoomNote="Zoomed y-axis: it does not start at 0. Fewer than 1 in 100 CVEs are ever listed."
          />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>When the risk is highest</CardTitle>
          <CardDescription>
            Baseline hazard of KEV listing per age band (listings per 100,000 average CVEs per day)
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          <BandsChart bands={bands} />
          <p>
            The first 30 days carry about <strong>{(first.rate_per_day / second.rate_per_day).toFixed(0)}×</strong>{' '}
            the hazard of days 30–90, and about <strong>{ratio.toFixed(0)}×</strong> the hazard after{' '}
            {bandLabel(later)}.
          </p>
          <p className="text-xs text-muted-foreground">
            Each band has at least 10 training listings ({bands.map((band) => band.train_listings).join(', ')}). Model{' '}
            {data.results.bands_model_version}.
          </p>
        </CardContent>
      </Card>
    </div>
  )
}

function HazardRatios({ data }: { data: TimingData }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>What moves the risk (hazard ratios)</CardTitle>
        <CardDescription>
          Post-KEV cohort, cut-off {data.results.main_cutoff}. Above 1 means listed sooner. Relative effects, not
          probabilities.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Feature</TableHead>
              <TableHead className="text-right">Hazard ratio</TableHead>
              <TableHead>95% CI</TableHead>
              <TableHead className="text-right">p</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.results.hazard_ratios.map((row) => (
              <TableRow key={row.feature} className={cn(row.p_value >= 0.05 && 'text-muted-foreground')}>
                <TableCell>{row.label}</TableCell>
                <TableCell className="text-right font-medium">{row.hazard_ratio.toFixed(2)}</TableCell>
                <TableCell>{ci(row.ci, 2)}</TableCell>
                <TableCell className="text-right">{row.p_value < 0.001 ? '< 0.001' : row.p_value.toFixed(3)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}

type Open = { detail: TimingDetail; context: string }

function Backtest({ data, onOpen }: { data: TimingData; onOpen: (open: Open) => void }) {
  const summary = data.backtest
  const rows = [...summary.per_cve].sort((a, b) => a.b_rank - b.b_rank)
  return (
    <Card>
      <CardHeader>
        <CardTitle>Back-test: KEV additions after {day(summary.decision_time)}</CardTitle>
        <CardDescription>
          The model trained only on data before {day(summary.decision_time)}. {summary.listed} CVEs were added to KEV
          in the next {summary.window_days} days; {summary.listed_published_after_decision} of them were published after
          that date, so they could not be scored. {summary.scored} were scored, among{' '}
          {summary.available_population.toLocaleString()} CVEs.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Of the {summary.scored} scored, ranked in the…</TableHead>
              <TableHead className="text-right">Survival model</TableHead>
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
          {summary.rank_note} One month and {summary.scored} CVEs: a small sample, shown as an illustration, not as a
          result.
        </p>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>CVE</TableHead>
              <TableHead className="text-right">Model rank</TableHead>
              <TableHead className="text-right">CVSS rank</TableHead>
              <TableHead className="text-right">CVSS</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((row) => (
              <TableRow
                key={row.cve_id}
                className="cursor-pointer"
                onClick={() =>
                  onOpen({
                    detail: data.cves.backtest[row.cve_id],
                    context: `Back-test at ${day(summary.decision_time)}`,
                  })
                }
              >
                <TableCell className="font-mono underline">{row.cve_id}</TableCell>
                <TableCell className="text-right">{Math.round(row.b_rank).toLocaleString()}</TableCell>
                <TableCell className="text-right">{Math.round(row.cvss_rank).toLocaleString()}</TableCell>
                <TableCell className="text-right">{row.cvss?.toFixed(1) ?? '—'}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}

function TopTable({ data, onOpen }: { data: TimingData; onOpen: (open: Open) => void }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          Top {data.top.length} at {day(data.meta.decision_time)}
        </CardTitle>
        <CardDescription>
          Highest 30-day estimates among CVEs not yet in KEV. Select a row for the detail.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="text-right">Rank</TableHead>
              <TableHead>CVE</TableHead>
              <TableHead>Published</TableHead>
              <TableHead className="text-right">CVSS</TableHead>
              <TableHead className="text-right">30-day estimate</TableHead>
              <TableHead className="text-right">Exploits</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.top.map((id) => {
              const detail = data.cves.current[id]
              return (
                <TableRow
                  key={id}
                  className="cursor-pointer"
                  onClick={() => onOpen({ detail, context: `Current, ${day(data.meta.decision_time)}` })}
                >
                  <TableCell className="text-right">{detail.rank === null ? '—' : Math.round(detail.rank)}</TableCell>
                  <TableCell className="font-mono underline">{id}</TableCell>
                  <TableCell>{detail.published}</TableCell>
                  <TableCell className="text-right">{detail.cvss?.toFixed(1) ?? '—'}</TableCell>
                  <TableCell className="text-right">
                    {detail.raw_30d === null ? statusLabels[detail.status] : `${(detail.raw_30d * 100).toFixed(3)}%`}
                  </TableCell>
                  <TableCell className="text-right">
                    {detail.evidence.filter((item) => item.kind === 'exploit').length}
                  </TableCell>
                </TableRow>
              )
            })}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}

function Limitations({ data }: { data: TimingData }) {
  return (
    <Card className="border-amber-500/40">
      <CardHeader>
        <CardTitle>Limitations</CardTitle>
      </CardHeader>
      <CardContent>
        <ul className="flex list-disc flex-col gap-1 pl-5">
          <li>{data.meta.note}</li>
          <li>
            The model ranks the whole list better than CVSS, but its top 100 is not better: P@100 is{' '}
            {data.results.main.post_kev.cox.p_at_100.toFixed(2)} against{' '}
            {data.results.main.post_kev.cvss.p_at_100.toFixed(2)} for CVSS.
          </li>
          <li>
            The early post-KEV cut-offs (2022–2023) have too few KEV listings to train on (fewer than 100); they are
            reported, not used as results.
          </li>
          <li>
            The 30-day estimate is a ranking score: its calibration has not been checked, so it is not a probability.
          </li>
          <li>KEV listing is not the first attack; it is a public, dated record of exploitation.</li>
        </ul>
      </CardContent>
    </Card>
  )
}

export function TimingPage() {
  const state = useTimingData()
  const [open, setOpen] = useState<Open | null>(null)

  if (state.status === 'loading') return <p className="text-muted-foreground">Loading exploit timing results…</p>
  if (state.status === 'error') return <MissingDataCard message={state.message} />
  const { data } = state

  if (open) {
    return (
      <div className="flex max-w-3xl flex-col gap-4">
        <Button variant="outline" size="sm" className="self-start" onClick={() => setOpen(null)}>
          Back to results
        </Button>
        <Card>
          <CardHeader>
            <CardTitle className="flex flex-wrap items-center gap-2 font-mono">
              {open.detail.cve_id} <RetrospectiveLabel />
            </CardTitle>
            <CardDescription>{open.context}</CardDescription>
          </CardHeader>
          <CardContent>
            <TimingDetailView detail={open.detail} />
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <RetrospectiveLabel />
        <span className="text-muted-foreground">
          Model {data.meta.model_version} · horizon {data.meta.horizon_days} days · data snapshot{' '}
          {data.meta.snapshot_date} · generated {day(data.meta.generated_at)}
        </span>
      </div>
      <Headline data={data} />
      <DifferenceTable data={data} />
      <Curves data={data} />
      <HazardRatios data={data} />
      <Backtest data={data} onOpen={setOpen} />
      <TopTable data={data} onOpen={setOpen} />
      <Limitations data={data} />
    </div>
  )
}
