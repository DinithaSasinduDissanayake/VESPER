// Owner: S.S.H. Thennakoon — Live timing: check one CVE (with what-if changes) and
// rank a list of CVEs for a patch deadline, using the live Cox model API.
import { useEffect, useState } from 'react'
import {
  checkCve,
  getModelInfo,
  planDeadline,
  predictWhatIf,
  type CveCheck,
  type Features,
  type ModelInfo,
  type PlanRow,
} from '@/api/bSurvival'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Textarea } from '@/components/ui/textarea'
import { LineChart } from './charts'
import { LevelBadge } from './TimingDetail'

// Eligible demo CVEs with clearly different results, plus one of each "no estimate" case.
const DEMO_CVES = [
  'CVE-2026-51134', // public exploit on publication day: High
  'CVE-2026-16940', // CVSS 10, no exploit: High; toggle the exploit to see the jump
  'CVE-2026-15964', // CVSS 9.8, no exploit: Medium
  'CVE-2026-20466', // physical access, CVSS 6.1: Low (middle of the population)
  'CVE-2026-66401', // physical access, CVSS 2.1: Low (bottom)
  'CVE-2021-44228', // Log4Shell: already in KEV
  'CVE-2019-0708', // before KEV began: not eligible
]

const percent = (value: number) => `${(value * 100).toFixed(2)}%`
const DAYS = ['30', '90', '365'] as const

// ---------------------------------------------------------------------------
// Check a CVE
// ---------------------------------------------------------------------------

function WhatIfForm({ features, info, onChange }: { features: Features; info: ModelInfo | null; onChange: (f: Features) => void }) {
  const select = (key: keyof Features, levels: string[] | undefined) => (
    <label className="flex flex-col gap-1 text-sm">
      {key.replace('_', ' ')}
      <NativeSelect value={String(features[key])} onChange={(e) => onChange({ ...features, [key]: e.target.value })}>
        {(levels ?? [String(features[key])]).map((level) => (
          <NativeSelectOption key={level} value={level}>
            {level.toLowerCase().replace('_', ' ')}
          </NativeSelectOption>
        ))}
      </NativeSelect>
    </label>
  )
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
      <label className="flex flex-col gap-1 text-sm">
        CVSS score
        <Input
          type="number"
          min={0}
          max={10}
          step={0.1}
          value={features.cvss_base_score ?? ''}
          onChange={(e) => onChange({ ...features, cvss_base_score: Number(e.target.value) })}
        />
      </label>
      {select('attack_vector', info?.levels.attack_vector)}
      {select('attack_complexity', info?.levels.attack_complexity)}
      {select('privileges_required', info?.levels.privileges_required)}
      {select('user_interaction', info?.levels.user_interaction)}
      <label className="flex flex-col gap-1 text-sm">
        CWE (weakness)
        <Input
          value={features.cwe_ids.join(';')}
          onChange={(e) => onChange({ ...features, cwe_ids: e.target.value.split(/[;,\s]+/).filter(Boolean) })}
        />
      </label>
      <label className="flex items-center gap-2 self-end pb-2 text-sm font-medium">
        <input
          type="checkbox"
          className="size-4"
          checked={features.public_exploit_at_publication}
          onChange={(e) => onChange({ ...features, public_exploit_at_publication: e.target.checked })}
        />
        Public exploit / PoC on publication day
      </label>
    </div>
  )
}

function EstimateView({ result, whatIf }: { result: CveCheck; whatIf: boolean }) {
  const estimate = result.estimate
  if (!estimate) return null
  const population = result.population.curve
  const top = Math.max(...estimate.curve.map(([, p]) => p), ...population.map(([, p]) => p))
  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {DAYS.map((d) => (
          <div key={d} className="rounded-md border p-3">
            <p className="text-sm text-muted-foreground">Listed in KEV by day {d}</p>
            <p className="text-2xl font-semibold">{percent(estimate.by_day[d])}</p>
          </div>
        ))}
        <div className="rounded-md border p-3">
          <p className="text-sm text-muted-foreground">Riskier than</p>
          <p className="flex items-center gap-2 text-2xl font-semibold">
            {percent(estimate.percentile)} <LevelBadge level={estimate.band} />
          </p>
          <p className="text-xs text-muted-foreground">of eligible CVEs (×{estimate.relative_risk.toFixed(2)} risk)</p>
        </div>
      </div>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <LineChart
          points={estimate.curve}
          compare={{ points: population, label: result.population.label, mainLabel: whatIf ? 'This what-if CVE' : 'This CVE' }}
          title="Model estimate of the chance of a KEV listing by days since publication"
          xLabel="Days since publication"
          yLabel="Chance listed in KEV"
          yDomain={[0, top * 1.1]}
          formatY={(value) => percent(value)}
        />
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Main drivers (vs an average CVE)</TableHead>
              <TableHead className="text-right">Hazard ratio</TableHead>
              <TableHead className="text-right">Effect</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {estimate.drivers.map((driver) => (
              <TableRow key={driver.feature}>
                <TableCell>{driver.label}</TableCell>
                <TableCell className="text-right">× {driver.hazard_ratio.toFixed(2)}</TableCell>
                <TableCell className={driver.effect > 0 ? 'text-right text-red-600' : 'text-right text-emerald-600'}>
                  {driver.effect > 0 ? '▲ raises' : '▼ lowers'} ({driver.effect.toFixed(2)})
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  )
}

function CheckCard({ info }: { info: ModelInfo | null }) {
  const [cveId, setCveId] = useState(DEMO_CVES[1])
  const [result, setResult] = useState<CveCheck | null>(null)
  const [features, setFeatures] = useState<Features | null>(null)
  const [whatIf, setWhatIf] = useState<CveCheck | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function check(id: string) {
    setCveId(id)
    setError(null)
    setWhatIf(null)
    try {
      const answer = await checkCve(id)
      setResult(answer)
      setFeatures(answer.features)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  async function change(next: Features) {
    setFeatures(next)
    try {
      setWhatIf(await predictWhatIf(next))
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  const shown = whatIf ?? result
  return (
    <Card>
      <CardHeader>
        <CardTitle>Check a CVE</CardTitle>
        <CardDescription>
          How soon is it likely to be exploited (added to CISA KEV)? Change the inputs to see what-if results.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <form
          className="flex flex-wrap gap-2"
          onSubmit={(e) => {
            e.preventDefault()
            void check(cveId)
          }}
        >
          <Input className="w-56 font-mono" value={cveId} onChange={(e) => setCveId(e.target.value)} />
          <Button type="submit">Check</Button>
        </form>
        {error && (
          <Alert variant="destructive">
            <AlertTitle>Could not get an estimate</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        {result && result.status !== 'available' && (
          <Alert>
            <AlertTitle>{result.status === 'already_exploited' ? 'Already exploited' : 'No estimate for this CVE'}</AlertTitle>
            <AlertDescription>{result.reason}</AlertDescription>
          </Alert>
        )}
        {result?.published && (
          <p className="text-sm text-muted-foreground">
            {result.cve_id} · published {result.published} ({result.age_days} days before {result.trained_through})
          </p>
        )}
        {features && features.cvss_base_score !== null && result?.estimate && (
          <WhatIfForm features={features} info={info} onChange={(next) => void change(next)} />
        )}
        {whatIf && (
          <p className="text-sm font-medium text-amber-700 dark:text-amber-400">
            Showing a what-if: the inputs above were changed from the real CVE.{' '}
            <button className="underline" onClick={() => void check(cveId)}>
              Reset
            </button>
          </p>
        )}
        {shown && <EstimateView result={shown} whatIf={Boolean(whatIf)} />}
        {shown && <p className="text-sm text-muted-foreground">{shown.note}</p>}
      </CardContent>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// Patch deadline planner
// ---------------------------------------------------------------------------

function PlannerCard() {
  const [text, setText] = useState(DEMO_CVES.join('\n'))
  const [deadline, setDeadline] = useState(30)
  const [rows, setRows] = useState<PlanRow[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function rank(days = deadline) {
    const ids = text.split(/[\s,;]+/).filter(Boolean)
    if (!ids.length) return
    try {
      setRows((await planDeadline(ids, days)).rows)
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Patch deadline planner</CardTitle>
        <CardDescription>
          Paste CVE IDs and pick a deadline: which ones are most likely to be exploited before you can patch?
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-[16rem_minmax(0,1fr)]">
          <Textarea className="h-40 font-mono" value={text} onChange={(e) => setText(e.target.value)} />
          <div className="flex flex-col gap-3">
            <label className="flex flex-col gap-1">
              Patch deadline: <strong>{deadline} days</strong>
              <input
                type="range"
                min={7}
                max={365}
                value={deadline}
                onChange={(e) => {
                  setDeadline(Number(e.target.value))
                  if (rows) void rank(Number(e.target.value))
                }}
              />
            </label>
            <Button className="self-start" onClick={() => void rank()}>
              Rank
            </Button>
            {error && <p className="text-sm text-red-600">{error}</p>}
          </div>
        </div>
        {rows && (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-10 text-right">#</TableHead>
                <TableHead>CVE</TableHead>
                <TableHead>Band</TableHead>
                <TableHead className="text-right">Chance before deadline</TableHead>
                <TableHead>Main driver</TableHead>
                <TableHead>Patch first?</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((row) => (
                <TableRow key={row.cve_id} className={row.status === 'not_eligible' ? 'text-muted-foreground' : ''}>
                  <TableCell className="text-right">{row.rank}</TableCell>
                  <TableCell className="font-mono">{row.cve_id}</TableCell>
                  <TableCell>
                    <LevelBadge level={row.band} status={row.status} />
                  </TableCell>
                  <TableCell className="text-right font-medium">
                    {row.p_before_deadline === null ? '—' : percent(row.p_before_deadline)}
                  </TableCell>
                  <TableCell className="whitespace-normal">{row.main_driver ?? row.reason ?? '—'}</TableCell>
                  <TableCell>{row.patch_first ? 'Yes' : ''}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        <p className="text-sm text-muted-foreground">
          Chance = model estimate of a KEV listing within the deadline, given none so far. Patch first = already in KEV,
          or in the top 5% of model risk (High). An estimate for ranking, not a certainty.
        </p>
      </CardContent>
    </Card>
  )
}

export function LiveTab() {
  const [info, setInfo] = useState<ModelInfo | null>(null)
  useEffect(() => {
    getModelInfo().then(setInfo, () => setInfo(null))
  }, [])
  return (
    <div className="flex flex-col gap-4">
      <p className="text-muted-foreground">
        Live answers from the Cox model
        {info && ` trained on ${info.train_rows.toLocaleString()} CVEs (${info.train_events} KEV listings) up to ${info.trained_through}`}
        . Estimates, not certainties.
      </p>
      <CheckCard info={info} />
      <PlannerCard />
    </div>
  )
}
