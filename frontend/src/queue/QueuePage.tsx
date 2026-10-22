import { useEffect, useState } from 'react'
import { ArrowDownToLine } from 'lucide-react'
import {
  downloadPlannerRanking,
  getPlannerRanking,
  type PlannerCandidate,
  type PlannerRanking,
} from '@/api/queue'
import { Button } from '@/components/ui/button'
import { CveDetail } from './CveDetail'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

const DISPLAY_COUNT = 25

function score(value: number | null) {
  return value === null ? '—' : value.toFixed(3)
}

function saveCsv(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

function RankingRows({ candidates, onSelect }: { candidates: PlannerCandidate[]; onSelect: (cveId: string) => void }) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="bg-blue-50/80 font-semibold text-blue-950 dark:bg-blue-950/50 dark:text-blue-100">Rank</TableHead>
          <TableHead className="bg-blue-50/80 font-semibold text-blue-950 dark:bg-blue-950/50 dark:text-blue-100">CVE</TableHead>
          <TableHead className="bg-blue-50/80 text-right font-semibold text-blue-950 dark:bg-blue-950/50 dark:text-blue-100">Risk score</TableHead>
          <TableHead className="bg-blue-50/80 text-right font-semibold text-blue-950 dark:bg-blue-950/50 dark:text-blue-100">Text (A)</TableHead>
          <TableHead className="bg-blue-50/80 text-right font-semibold text-blue-950 dark:bg-blue-950/50 dark:text-blue-100">Timing (B)</TableHead>
          <TableHead className="bg-blue-50/80 text-right font-semibold text-blue-950 dark:bg-blue-950/50 dark:text-blue-100">Structural signal (C)</TableHead>
          <TableHead className="bg-blue-50/80 text-right font-semibold text-blue-950 dark:bg-blue-950/50 dark:text-blue-100">CVSS</TableHead>
          <TableHead className="bg-blue-50/80 text-right font-semibold text-blue-950 dark:bg-blue-950/50 dark:text-blue-100">EPSS</TableHead>
          <TableHead className="bg-blue-50/80 text-right font-semibold text-blue-950 dark:bg-blue-950/50 dark:text-blue-100">Signals</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {candidates.map((candidate) => (
          <TableRow key={candidate.cve_id} className="transition-colors hover:bg-blue-50/70 dark:hover:bg-blue-950/30">
            <TableCell>
              <span className="inline-flex min-w-8 justify-center rounded-md bg-blue-50 px-2 py-1 text-xs font-bold text-blue-800 dark:bg-blue-950 dark:text-blue-200">
                {candidate.model_rank}
              </span>
            </TableCell>
            <TableCell>
              <button
                type="button"
                className="font-mono font-medium text-blue-800 underline-offset-4 hover:text-blue-600 hover:underline focus-visible:rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring dark:text-blue-200 dark:hover:text-blue-100"
                onClick={() => onSelect(candidate.cve_id)}
                aria-label={`Open details for ${candidate.cve_id}`}
              >
                {candidate.cve_id}
              </button>
            </TableCell>
            <TableCell className="text-right font-semibold tabular-nums text-blue-950 dark:text-blue-100">{score(candidate.risk_score)}</TableCell>
            <TableCell className="text-right">{score(candidate.score_a)}</TableCell>
            <TableCell className="text-right">{score(candidate.score_b)}</TableCell>
            <TableCell className="text-right" title={candidate.reason_c ?? undefined}>
              {candidate.status_c && candidate.status_c !== 'available'
                ? candidate.status_c
                : score(candidate.score_c)}
            </TableCell>
            <TableCell className="text-right">{score(candidate.cvss_base_score)}</TableCell>
            <TableCell className="text-right">{score(candidate.epss_score)}</TableCell>
            <TableCell className="text-right">
              {candidate.signals_used === null ? '—' : `${candidate.signals_used}/5`}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

export function QueuePage() {
  const [ranking, setRanking] = useState<PlannerRanking | null>(null)
  const [selectedCveId, setSelectedCveId] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [downloading, setDownloading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    setError(null)
    getPlannerRanking(controller.signal)
      .then(setRanking)
      .catch((reason: unknown) => {
        if (!controller.signal.aborted) {
          setError(reason instanceof Error ? reason.message : 'Could not load the risk ranking.')
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false)
      })
    return () => controller.abort()
  }, [])

  async function handleDownload() {
    setDownloading(true)
    setError(null)
    try {
      const csv = await downloadPlannerRanking()
      saveCsv(csv, ranking?.ranking_file ?? 'vesper_current_ranking.csv')
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Could not download the ranking CSV.')
    } finally {
      setDownloading(false)
    }
  }

  const topCandidates = ranking?.vulnerabilities.slice(0, DISPLAY_COUNT) ?? []
  const selectedCandidate = topCandidates.find((candidate) => candidate.cve_id === selectedCveId)

  if (selectedCandidate) {
    return <CveDetail candidate={selectedCandidate} onBack={() => setSelectedCveId(null)} />
  }

  return (
    <section className="space-y-5">
      <div className="queue-hero-pattern relative isolate flex flex-wrap items-center justify-between gap-4 overflow-hidden rounded-2xl border border-blue-900/20 p-5 text-white shadow-lg shadow-blue-950/10 md:p-6">
        <div aria-hidden="true" className="pointer-events-none absolute -right-12 -top-24 z-0 size-72 rounded-full border border-white/10" />
        <div aria-hidden="true" className="pointer-events-none absolute -right-2 -top-14 z-0 size-52 rounded-full border border-white/10" />
        <div className="relative z-10">
          <div className="mb-2 flex items-center gap-2">
            <h2 className="text-lg font-semibold tracking-tight text-white">Top prioritized vulnerabilities</h2>
            <span className="rounded-full border border-white/20 bg-white/10 px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-sky-100 backdrop-blur">
              Provisional
            </span>
          </div>
          <p className="text-sm text-blue-100/85">
            Five-signal composite ranking; this is not a trained or validated model.
          </p>
          {ranking && (
            <p className="mt-1.5 text-xs font-medium text-sky-200">
              Showing top {topCandidates.length} of {ranking.count.toLocaleString()} CVEs
              {ranking.vulnerabilities[0]?.data_as_of
                ? ` · data as of ${ranking.vulnerabilities[0].data_as_of}`
                : ''}
            </p>
          )}
        </div>
        <Button onClick={handleDownload} disabled={loading || downloading || !ranking} className="relative z-10 border border-white/25 bg-white text-blue-900 shadow-md hover:bg-blue-50">
          <ArrowDownToLine />
          {downloading ? 'Preparing CSV…' : 'Download full ranking CSV'}
        </Button>
      </div>

      {loading ? (
        <p role="status" className="text-muted-foreground">Loading current ranking…</p>
      ) : error ? (
        <div role="alert" className="space-y-2 rounded-md border border-destructive/40 p-4">
          <p className="font-medium">Could not load the current ranking: {error}</p>
          <p className="text-sm text-muted-foreground">
            Confirm the API is running and the current ranking CSV has been generated.
          </p>
        </div>
      ) : topCandidates.length === 0 ? (
        <p className="text-muted-foreground">The ranking is available but contains no CVEs.</p>
      ) : (
        <div className="overflow-x-auto rounded-xl border bg-card shadow-sm">
          <RankingRows candidates={topCandidates} onSelect={setSelectedCveId} />
        </div>
      )}
    </section>
  )
}
