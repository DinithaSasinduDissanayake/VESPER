// Real model output for one CVE at one decision time (from the demo JSON).
import { ExternalLink } from 'lucide-react'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { statusLabels } from '@/queue/format'
import { LineChart } from './charts'
import { day, percentText, zoomedDomain } from './format'
import type { TimingDetail as Detail } from './types'

export function RetrospectiveLabel({ text = 'Model output (retrospective)' }: { text?: string }) {
  return (
    <span className="rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-xs font-medium text-amber-800 dark:text-amber-300">
      {text}
    </span>
  )
}

function Headline({ detail }: { detail: Detail }) {
  return (
    <dl className="grid grid-cols-2 gap-x-4 gap-y-1">
      {detail.raw_30d !== null && detail.percentile !== null && detail.rank !== null ? (
        <>
          <dt className="text-muted-foreground">30-day estimate</dt>
          <dd className="font-semibold">{percentText(detail.raw_30d, 3)}</dd>
          <dt className="text-muted-foreground">Percentile</dt>
          <dd className="font-semibold">
            {(detail.percentile * 100).toFixed(2)} (rank {Math.round(detail.rank).toLocaleString()} of{' '}
            {detail.rank_of.toLocaleString()})
          </dd>
        </>
      ) : (
        <>
          <dt className="text-muted-foreground">Status</dt>
          <dd className="font-semibold">{statusLabels[detail.status]}</dd>
          {detail.reason && (
            <>
              <dt className="text-muted-foreground">Reason</dt>
              <dd>{detail.reason}</dd>
            </>
          )}
        </>
      )}
      <dt className="text-muted-foreground">Decision time</dt>
      <dd>{day(detail.decision_time)} (00:00 UTC)</dd>
      <dt className="text-muted-foreground">Trained through</dt>
      <dd>{day(detail.trained_through)}</dd>
      <dt className="text-muted-foreground">Published / age</dt>
      <dd>
        {detail.published} · {detail.age_days} days
      </dd>
      <dt className="text-muted-foreground">CVSS / CWE</dt>
      <dd>
        {detail.cvss?.toFixed(1) ?? '—'} · {detail.cwe.join(', ') || '—'}
      </dd>
      <dt className="text-muted-foreground">Model version</dt>
      <dd className="font-mono text-xs">{detail.model_version}</dd>
    </dl>
  )
}

function SurvivalCurve({ detail }: { detail: Detail }) {
  if (!detail.survival) return null
  const points = detail.survival.map((value, d): [number, number] => [d, value])
  return (
    <div className="flex flex-col gap-1">
      <h3 className="font-medium">Survival curve, next {detail.survival.length - 1} days</h3>
      <LineChart
        points={points}
        title={`Chance that ${detail.cve_id} is not yet in KEV`}
        xLabel="Days after the decision time"
        yLabel="Not yet in KEV"
        yDomain={zoomedDomain(detail.survival)}
        formatY={(value) => percentText(value, 3)}
        zoomNote="Zoomed y-axis: it does not start at 0, the values are all close to 100%."
      />
      <p className="text-xs text-muted-foreground">
        Chance of not being added to KEV. KEV listing is not the first attack.
      </p>
    </div>
  )
}

function Evidence({ detail }: { detail: Detail }) {
  const exploits = detail.evidence.filter((item) => item.kind === 'exploit')
  // One list in date order; a KEV listing after the decision time is the outcome, shown apart
  const items = [...detail.evidence]
  if (detail.kev && !detail.kev.after_decision) {
    items.push({ kind: 'kev', date: detail.kev.date, label: 'Added to CISA KEV' })
  }
  items.sort((a, b) => a.date.localeCompare(b.date))
  return (
    <div className="flex flex-col gap-1">
      <h3 className="font-medium">Evidence before the decision time</h3>
      <ol className="flex flex-col gap-1 border-l pl-4">
        {items.map((item) => (
          <li key={`${item.kind}-${item.label}`}>
            <span className="font-mono text-xs text-muted-foreground">{item.date}</span>{' '}
            {item.url ? (
              <a href={item.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 underline">
                {item.label} <ExternalLink className="size-3" />
              </a>
            ) : (
              item.label
            )}
          </li>
        ))}
      </ol>
      {exploits.length === 0 && (
        <p className="text-xs text-muted-foreground">
          No dated public exploit found at this date. This does not prove that no exploit exists.
        </p>
      )}
      {detail.kev?.after_decision && (
        <p className="text-xs">
          Outcome (not known at the decision time): added to CISA KEV on <strong>{detail.kev.date}</strong>.
        </p>
      )}
    </div>
  )
}

function Factors({ detail }: { detail: Detail }) {
  if (detail.factors.length === 0) return null
  return (
    <div className="flex flex-col gap-1">
      <h3 className="font-medium">Top factors</h3>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Feature</TableHead>
            <TableHead className="text-right">Hazard ratio</TableHead>
            <TableHead className="text-right">Effect for this CVE</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {detail.factors.map((factor) => (
            <TableRow key={factor.feature}>
              <TableCell>{factor.label}</TableCell>
              <TableCell className="text-right">{factor.hazard_ratio.toFixed(2)}</TableCell>
              <TableCell className="text-right">× {Math.exp(factor.log_effect).toFixed(2)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <p className="text-xs text-muted-foreground">
        Relative effects on the hazard, compared with an average training CVE. They multiply the risk; they are not
        parts of the probability. The CVSS hazard ratio is per standard deviation.
      </p>
    </div>
  )
}

export function TimingDetailView({ detail }: { detail: Detail }) {
  return (
    <div className="flex flex-col gap-4">
      <Headline detail={detail} />
      <SurvivalCurve detail={detail} />
      <Evidence detail={detail} />
      <Factors detail={detail} />
    </div>
  )
}
