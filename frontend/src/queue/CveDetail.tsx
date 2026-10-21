import { useEffect, useState } from 'react'
import { ArrowLeft, ExternalLink, ShieldAlert } from 'lucide-react'
import { getCveDetails, type PlannerCandidate, type VulnerabilityFacts } from '@/api/queue'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'

type CveDetailProps = {
  candidate: PlannerCandidate
  onBack: () => void
}

function displayScore(value: number | null, digits = 3) {
  return value === null ? 'Unavailable' : value.toFixed(digits)
}

function formatDate(value: string) {
  const parsed = new Date(value)
  return Number.isNaN(parsed.valueOf()) ? value : parsed.toLocaleString()
}

function SignalCard({ title, value, status, reason, note, digits = 3 }: {
  title: string
  value: number | null
  digits?: number
  status?: string | null
  reason?: string | null
  note?: string
}) {
  return (
    <Card className="border-blue-100/80 shadow-sm dark:border-blue-900/60">
      <CardHeader className="pb-2">
        <CardDescription>{title}</CardDescription>
        <CardTitle className="text-2xl font-semibold tabular-nums text-blue-900 dark:text-blue-100">
          {displayScore(value, digits)}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-1 text-xs text-muted-foreground">
        {status && <p>Status: <span className="font-medium text-foreground">{status.replaceAll('_', ' ')}</span></p>}
        {reason && <p>{reason}</p>}
        {note && <p>{note}</p>}
      </CardContent>
    </Card>
  )
}

function FactsView({ facts, candidate }: { facts: VulnerabilityFacts; candidate: PlannerCandidate }) {
  return (
    <div className="space-y-5">
      <Card className="overflow-hidden border-blue-100/80 shadow-sm dark:border-blue-900/60">
        <CardHeader className="border-b bg-blue-50/60 dark:bg-blue-950/20">
          <CardTitle className="text-base">Description</CardTitle>
        </CardHeader>
        <CardContent className="pt-4">
          <p className="whitespace-pre-wrap leading-6">{facts.description || 'No description is recorded in the local NVD snapshot.'}</p>
          <a
            className="mt-4 inline-flex items-center gap-1 text-sm font-medium text-primary hover:underline"
            href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(facts.cve_id)}`}
            target="_blank"
            rel="noreferrer"
          >
            Open NVD record <ExternalLink className="size-3.5" />
          </a>
        </CardContent>
      </Card>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {[
          ['Published', facts.published_at],
          ['NVD last modified', facts.last_modified_at],
          ['NVD status', facts.nvd_status || 'Not provided'],
          ['Local NVD snapshot', facts.snapshot_date],
        ].map(([label, value]) => (
          <Card key={label} className="border-blue-100/80 shadow-sm dark:border-blue-900/60">
            <CardContent className="pt-4">
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
              <p className="mt-2 break-words text-sm font-semibold">{label.includes('status') ? value : formatDate(value)}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <section>
        <div className="mb-3">
          <h3 className="font-semibold">Risk and evidence signals</h3>
          <p className="mt-1 text-xs text-muted-foreground">Model ranking values come from the current Component D ranking; CVE facts come from the local NVD snapshot.</p>
        </div>
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          <SignalCard title="Provisional risk score · rank" value={candidate.risk_score} note={`Rank ${candidate.model_rank} · ${candidate.signals_used ?? '—'} of 5 signals used`} />
          <SignalCard title="Text signal (A)" value={candidate.score_a} status={candidate.status_a} reason={candidate.reason_a} />
          <SignalCard title="Exploit timing (B)" value={candidate.score_b} status={candidate.status_b} reason={candidate.reason_b} />
          <SignalCard title="Exposure (C)" value={candidate.score_c} status={candidate.status_c} reason={candidate.reason_c} note="Structural graph signal; not an exploitation probability." />
          <SignalCard title={`CVSS${facts.cvss_version ? ` ${facts.cvss_version}` : ''}`} value={facts.cvss_base_score} digits={1} note={facts.cvss_vector ? `Vector: ${facts.cvss_vector}` : 'CVSS vector unavailable'} />
          <SignalCard title="EPSS" value={candidate.epss_score} note={candidate.epss_date ? `Snapshot: ${candidate.epss_date}` : 'Exploit prediction score'} />
        </div>
      </section>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="border-blue-100/80 shadow-sm dark:border-blue-900/60">
          <CardHeader>
            <CardTitle className="text-base">Affected products</CardTitle>
            <CardDescription>{facts.affected.length} vendor and product entries from NVD</CardDescription>
          </CardHeader>
          <CardContent>
            {facts.affected.length ? (
              <div className="max-h-64 space-y-2 overflow-y-auto">
                {facts.affected.map(([vendor, product], index) => (
                  <div key={`${vendor}-${product}-${index}`} className="grid grid-cols-[minmax(0,0.7fr)_minmax(0,1.3fr)] gap-3 rounded-lg border bg-background px-3 py-2 text-sm">
                    <span className="break-words font-medium text-blue-800 dark:text-blue-200">{vendor}</span>
                    <span className="break-words text-muted-foreground">{product}</span>
                  </div>
                ))}
              </div>
            ) : <p className="text-sm text-muted-foreground">No affected product configuration is recorded.</p>}
          </CardContent>
        </Card>

        <Card className="border-blue-100/80 shadow-sm dark:border-blue-900/60">
          <CardHeader>
            <CardTitle className="text-base">Weaknesses</CardTitle>
            <CardDescription>CWE identifiers supplied with the NVD record</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            {facts.cwe_ids.length ? facts.cwe_ids.map((cwe) => (
              <span key={cwe} className="rounded-full border border-blue-200 bg-blue-50 px-3 py-1 text-xs font-semibold text-blue-800 dark:border-blue-800 dark:bg-blue-950 dark:text-blue-200">{cwe}</span>
            )) : <p className="text-sm text-muted-foreground">No CWE identifiers are recorded.</p>}
          </CardContent>
        </Card>
      </div>

      <Card className="border-blue-100/80 shadow-sm dark:border-blue-900/60">
        <CardHeader>
          <CardTitle className="text-base">Ranking provenance</CardTitle>
          <CardDescription>The provisional composite and its source snapshots.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
          {[
            ['Text snapshot', candidate.snapshot_date_a],
            ['Timing snapshot', candidate.snapshot_date_b],
            ['Exposure snapshot', candidate.snapshot_date_c],
            ['Baseline snapshot', candidate.baseline_snapshot_date],
          ].map(([label, value]) => (
            <div key={label}>
              <p className="text-xs text-muted-foreground">{label}</p>
              <p className="mt-1 font-medium">{value ?? 'Unavailable'}</p>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  )
}

export function CveDetail({ candidate, onBack }: CveDetailProps) {
  const [facts, setFacts] = useState<VulnerabilityFacts | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const controller = new AbortController()
    setFacts(null)
    setError(null)
    setLoading(true)
    getCveDetails(candidate.cve_id, controller.signal)
      .then(setFacts)
      .catch((reason: unknown) => {
        if (!controller.signal.aborted) {
          setError(reason instanceof Error ? reason.message : 'Could not load CVE details.')
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false)
      })
    return () => controller.abort()
  }, [candidate.cve_id])

  return (
    <div className="space-y-5">
      <Button variant="outline" size="sm" className="border-blue-200 bg-card text-blue-800 hover:bg-blue-50 dark:border-blue-800 dark:text-blue-200 dark:hover:bg-blue-950" onClick={onBack}>
        <ArrowLeft /> Back to priority queue
      </Button>

      <div className="rounded-2xl border border-blue-100 bg-gradient-to-r from-white to-blue-50 p-5 shadow-sm dark:border-blue-900/60 dark:from-card dark:to-blue-950/30">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wider text-blue-700 dark:text-blue-300">Vulnerability record</p>
            <h2 className="mt-1 font-mono text-2xl font-bold tracking-tight">{candidate.cve_id}</h2>
            <p className="mt-1 text-sm text-muted-foreground">Details from the local NVD snapshot and current Component D ranking.</p>
          </div>
          <div className="flex items-center gap-3">
            <span className="rounded-lg border border-blue-200 bg-white px-3 py-2 text-sm font-semibold text-blue-900 dark:border-blue-800 dark:bg-blue-950 dark:text-blue-100">Rank #{candidate.model_rank}</span>
            <span className="rounded-lg bg-blue-700 px-3 py-2 text-sm font-bold tabular-nums text-white">Risk {candidate.risk_score.toFixed(3)}</span>
          </div>
        </div>
      </div>

      {loading ? (
        <div role="status" className="rounded-xl border bg-card p-6 text-sm text-muted-foreground">Loading NVD details…</div>
      ) : error ? (
        <div role="alert" className="flex gap-3 rounded-xl border border-amber-300 bg-amber-50 p-5 text-amber-950 dark:border-amber-900 dark:bg-amber-950/30 dark:text-amber-100">
          <ShieldAlert className="mt-0.5 size-5 shrink-0" />
          <div>
            <p className="font-semibold">NVD details could not be loaded.</p>
            <p className="mt-1 text-sm">{error}</p>
            <p className="mt-2 text-xs opacity-80">The ranking row is real; descriptive details require the local processed NVD file at data/processed/vulnerabilities.parquet.</p>
          </div>
        </div>
      ) : facts ? (
        <FactsView facts={facts} candidate={candidate} />
      ) : null}
    </div>
  )
}
