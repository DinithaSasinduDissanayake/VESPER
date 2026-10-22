import { useEffect, useState } from 'react'
import { ArrowDownToLine, CircleAlert } from 'lucide-react'
import {
  downloadPlannerRanking,
  getPlannerRanking,
  type PlannerCandidate,
  type PlannerRanking,
} from '@/api/queue'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
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
          <TableHead>Rank</TableHead>
          <TableHead>CVE</TableHead>
          <TableHead className="text-right">Risk score</TableHead>
          <TableHead className="text-right">Text (A)</TableHead>
          <TableHead className="text-right">Timing (B)</TableHead>
          <TableHead className="text-right">Exposure (C)</TableHead>
          <TableHead className="text-right">CVSS</TableHead>
          <TableHead className="text-right">EPSS</TableHead>
          <TableHead className="text-right">Signals</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {candidates.map((candidate) => (
          <TableRow key={candidate.cve_id}>
            <TableCell className="tabular-nums text-muted-foreground">{candidate.model_rank}</TableCell>
            <TableCell>
              <button
                type="button"
                className="rounded-sm font-mono font-medium underline-offset-4 outline-none hover:underline focus-visible:ring-3 focus-visible:ring-ring/50"
                onClick={() => onSelect(candidate.cve_id)}
                aria-label={`Open details for ${candidate.cve_id}`}
              >
                {candidate.cve_id}
              </button>
            </TableCell>
            <TableCell className="text-right font-medium tabular-nums">{score(candidate.risk_score)}</TableCell>
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
    <section className="flex flex-col gap-4">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-2">
            <h2 className="text-xl font-semibold tracking-tight">Top prioritized vulnerabilities</h2>
            <Badge variant="outline">Provisional</Badge>
          </div>
          <p className="text-muted-foreground">
            Five-signal composite ranking; this is not a trained or validated model.
          </p>
          {ranking && (
            <p className="text-xs text-muted-foreground">
              Showing top {topCandidates.length} of {ranking.count.toLocaleString()} CVEs
              {ranking.vulnerabilities[0]?.data_as_of
                ? ` · data as of ${ranking.vulnerabilities[0].data_as_of}`
                : ''}
            </p>
          )}
        </div>
        <Button variant="outline" onClick={handleDownload} disabled={loading || downloading || !ranking}>
          <ArrowDownToLine data-icon="inline-start" />
          {downloading ? 'Preparing CSV…' : 'Download full ranking CSV'}
        </Button>
      </div>

      {loading ? (
        <p role="status" className="text-muted-foreground">Loading current ranking…</p>
      ) : error ? (
        <Alert variant="destructive">
          <CircleAlert />
          <AlertTitle>Could not load the current ranking: {error}</AlertTitle>
          <AlertDescription>
            Confirm the API is running and the current ranking CSV has been generated.
          </AlertDescription>
        </Alert>
      ) : topCandidates.length === 0 ? (
        <p className="text-muted-foreground">The ranking is available but contains no CVEs.</p>
      ) : (
        <Card className="py-0">
          <RankingRows candidates={topCandidates} onSelect={setSelectedCveId} />
        </Card>
      )}
    </section>
  )
}
