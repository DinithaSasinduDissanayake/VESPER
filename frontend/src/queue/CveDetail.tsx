import { useEffect, useState } from 'react'
import { ArrowLeft, ExternalLink, ShieldAlert } from 'lucide-react'
import { getCveDetails, type PlannerCandidate, type VulnerabilityFacts } from '@/api/queue'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { ExposureSection } from '@/exposure/ExposureSection'
import { useComponentCDetails } from '@/exposure/data'
import { TimingSection } from '@/timing/TimingSection'
import type { QueueItem } from './types'

type CveDetailProps = {
  candidate: PlannerCandidate
  onBack: () => void
}

// TimingSection reads a queue row; build one from the planner row and NVD facts.
function timingItem(facts: VulnerabilityFacts, candidate: PlannerCandidate): QueueItem {
  return {
    vulnerability: {
      cve_id: candidate.cve_id,
      description: facts.description,
      cvss_base_score: facts.cvss_base_score,
      affected: facts.affected,
    },
    epss: candidate.epss_score,
    scores: [],
  }
}

function displayScore(value: number | null, digits = 3) {
  return value === null ? 'Unavailable' : value.toFixed(digits)
}

// NVD text often carries hard line breaks and runs of blank lines; keep paragraph
// breaks but collapse the rest so the card has no large empty gaps.
function descriptionParagraphs(description: string) {
  const paragraphs = description
    .split(/\n\s*\n/)
    .map((paragraph) => paragraph.replace(/\s+/g, ' ').trim())
    .filter(Boolean)
  return paragraphs.length ? paragraphs : ['No description is recorded in the local NVD snapshot.']
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
    <Card>
      <CardHeader>
        <CardDescription>{title}</CardDescription>
        <CardTitle className="text-2xl font-semibold tabular-nums">
          {displayScore(value, digits)}
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-1 text-muted-foreground">
        {status && <p>Status: <span className="font-medium text-foreground">{status.replaceAll('_', ' ')}</span></p>}
        {reason && <p>{reason}</p>}
        {note && <p>{note}</p>}
      </CardContent>
    </Card>
  )
}

function FactsView({ facts, candidate }: { facts: VulnerabilityFacts; candidate: PlannerCandidate }) {
  return (
    <div className="flex flex-col gap-5">
      <Card>
        <CardHeader>
          <CardTitle>Description</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col items-start gap-2">
          {descriptionParagraphs(facts.description).map((paragraph, index) => (
            <p key={index} className="max-w-[80ch] text-base leading-7">{paragraph}</p>
          ))}
          <Button variant="link" className="px-0" asChild>
            <a
              href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(facts.cve_id)}`}
              target="_blank"
              rel="noreferrer"
            >
              Open NVD record <ExternalLink data-icon="inline-end" />
            </a>
          </Button>
        </CardContent>
      </Card>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {[
          ['Published', facts.published_at],
          ['NVD last modified', facts.last_modified_at],
          ['NVD status', facts.nvd_status || 'Not provided'],
          ['Local NVD snapshot', facts.snapshot_date],
        ].map(([label, value]) => (
          <Card key={label} size="sm">
            <CardHeader>
              <CardDescription>{label}</CardDescription>
              <CardTitle className="break-words">{label.includes('status') ? value : formatDate(value)}</CardTitle>
            </CardHeader>
          </Card>
        ))}
      </div>

      <section className="flex flex-col gap-3">
        <div className="flex flex-col gap-1">
          <h3 className="text-lg font-medium">Risk and evidence signals</h3>
          <p className="text-sm text-muted-foreground">Model ranking values come from the current Component D ranking; CVE facts come from the local NVD snapshot.</p>
        </div>
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          <SignalCard title="Provisional risk score · rank" value={candidate.risk_score} note={`Rank ${candidate.model_rank} · ${candidate.signals_used ?? '—'} of 5 signals used`} />
          <SignalCard title="Text signal (A)" value={candidate.score_a} status={candidate.status_a} reason={candidate.reason_a} />
          <SignalCard title="Exploit timing (B)" value={candidate.score_b} status={candidate.status_b} reason={candidate.reason_b} />
          <SignalCard title="Structural signal · ranking input" value={candidate.status_c && candidate.status_c !== 'available' ? null : candidate.score_c} status={candidate.status_c} reason={candidate.reason_c} note="Preserved from D's ranking. Source model version is not exposed by this ranking API; see the artifact-backed panel separately." />
          <SignalCard title={`CVSS${facts.cvss_version ? ` ${facts.cvss_version}` : ''}`} value={facts.cvss_base_score} digits={1} note={facts.cvss_vector ? `Vector: ${facts.cvss_vector}` : 'CVSS vector unavailable'} />
          <SignalCard title="EPSS" value={candidate.epss_score} note={candidate.epss_date ? `Snapshot: ${candidate.epss_date}` : 'Exploit prediction score'} />
        </div>
      </section>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Affected products</CardTitle>
            <CardDescription>{facts.affected.length} vendor and product entries from NVD</CardDescription>
          </CardHeader>
          <CardContent>
            {facts.affected.length ? (
              <div className="flex max-h-64 flex-col gap-2 overflow-y-auto">
                {facts.affected.map(([vendor, product], index) => (
                  <div key={`${vendor}-${product}-${index}`} className="grid grid-cols-[minmax(0,0.7fr)_minmax(0,1.3fr)] gap-3 rounded-md bg-muted/50 px-3 py-2 text-sm">
                    <span className="break-words font-medium">{vendor}</span>
                    <span className="break-words text-muted-foreground">{product}</span>
                  </div>
                ))}
              </div>
            ) : <p className="text-sm text-muted-foreground">No affected product configuration is recorded.</p>}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Weaknesses</CardTitle>
            <CardDescription>CWE identifiers supplied with the NVD record</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            {facts.cwe_ids.length ? facts.cwe_ids.map((cwe) => (
              <Badge key={cwe} variant="outline">{cwe}</Badge>
            )) : <p className="text-sm text-muted-foreground">No CWE identifiers are recorded.</p>}
          </CardContent>
        </Card>

        <div className="min-w-0 empty:hidden lg:col-span-2">
          <TimingSection item={timingItem(facts, candidate)} />
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Ranking provenance</CardTitle>
          <CardDescription>The provisional composite and its source snapshots.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
          {[
            ['Text (A) score file date', candidate.snapshot_date_a],
            ['Timing snapshot', candidate.snapshot_date_b],
            ['Structural signal snapshot', candidate.snapshot_date_c],
            ['Baseline snapshot', candidate.baseline_snapshot_date],
          ].map(([label, value]) => (
            <div key={label} className="flex flex-col gap-1">
              <p className="text-muted-foreground">{label}</p>
              <p className="font-medium">{value ?? 'Unavailable'}</p>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  )
}

export function CveDetail({ candidate, onBack }: CveDetailProps) {
  const structural = useComponentCDetails(candidate.cve_id)
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
    <div className="flex flex-col gap-5">
      <Button variant="outline" className="self-start" onClick={onBack}>
        <ArrowLeft data-icon="inline-start" /> Back to priority queue
      </Button>

      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex flex-col gap-1">
          <p className="text-sm text-muted-foreground">Vulnerability record</p>
          <h2 className="font-mono text-2xl font-semibold tracking-tight">{candidate.cve_id}</h2>
          <p className="text-muted-foreground">Details from the local NVD snapshot and current Component D ranking.</p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline">Rank #{candidate.model_rank}</Badge>
          <Badge className="tabular-nums">Risk {candidate.risk_score.toFixed(3)}</Badge>
        </div>
      </div>

      {loading ? (
        <Card role="status">
          <CardContent className="text-muted-foreground">Loading NVD details…</CardContent>
        </Card>
      ) : error ? (
        <Alert>
          <ShieldAlert />
          <AlertTitle>NVD details could not be loaded.</AlertTitle>
          <AlertDescription>
            <p>{error}</p>
            <p>The ranking row is real; descriptive details require the local processed NVD file at data/processed/vulnerabilities.parquet.</p>
          </AlertDescription>
        </Alert>
      ) : facts ? (
        <FactsView facts={facts} candidate={candidate} />
      ) : null}
      <p className="text-xs text-muted-foreground">The structural panel uses its own declared artifact snapshot. The ranking input above may refer to a different source snapshot.</p>
      <ExposureSection key={candidate.cve_id} resource={structural} />
    </div>
  )
}
