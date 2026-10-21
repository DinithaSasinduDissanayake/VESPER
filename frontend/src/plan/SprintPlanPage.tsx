import { useEffect, useMemo, useState } from 'react'
import { ArrowDownToLine, RefreshCw, ShieldAlert } from 'lucide-react'
import {
  createPlannerPlan,
  downloadPlannerRanking,
  getPlannerRanking,
  type PlannedCandidate,
  type PlannerCandidate,
  type PlannerOverride,
  type PlannerPeriod,
  type PlannerRanking,
  type PlannerResponse,
} from '@/api/queue'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

const PAGE_SIZE = 20
type View = 'ranking' | 'plan'

function localToday() {
  const now = new Date()
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`
}

function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

function downloadPlanCsv(plan: PlannerResponse) {
  const quote = (value: string | number | null) => `"${String(value ?? '').replaceAll('"', '""')}"`
  const columns = [
    'cve_id', 'risk_rank', 'risk_score', 'patch_hours_estimated', 'effort_method',
    'business_criticality', 'priority_value', 'selection_status', 'planned_date', 'reason',
  ]
  const rows = [...plan.scheduled, ...plan.deferred]
    .sort((left, right) => left.model_rank - right.model_rank)
    .map((item) => [
      item.cve_id,
      item.model_rank,
      item.risk_score.toFixed(6),
      item.patch_hours,
      item.patch_hours_method,
      item.business_criticality,
      item.priority_value.toFixed(6),
      item.selected ? 'scheduled' : 'deferred',
      item.planned_date,
      item.reason,
    ].map(quote).join(','))
  saveBlob(
    new Blob([[columns.map(quote).join(','), ...rows].join('\r\n')], { type: 'text/csv;charset=utf-8' }),
    `vesper_${plan.planning_period}_patch_plan.csv`,
  )
}

function displayValue(value: number | null, digits = 3) {
  return value === null ? '—' : value.toFixed(digits)
}

function planRow(item: PlannedCandidate): PlannerCandidate {
  return item
}

export function SprintPlanPage() {
  const [ranking, setRanking] = useState<PlannerRanking | null>(null)
  const [patchers, setPatchers] = useState(3)
  const [hoursPerPatcher, setHoursPerPatcher] = useState(6)
  const [startDate, setStartDate] = useState(localToday)
  const [view, setView] = useState<View>('ranking')
  const [plan, setPlan] = useState<PlannerResponse | null>(null)
  const [overrides, setOverrides] = useState<Record<string, Omit<PlannerOverride, 'cve_id'>>>({})
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(0)
  const [rankingLoading, setRankingLoading] = useState(true)
  const [planning, setPlanning] = useState(false)
  const [downloadingRanking, setDownloadingRanking] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [reloadKey, setReloadKey] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    setRankingLoading(true)
    getPlannerRanking(controller.signal)
      .then((response) => {
        setRanking(response)
        setPlan(null)
        setPage(0)
      })
      .catch((reason: unknown) => {
        if (controller.signal.aborted) return
        setRanking(null)
        setError(reason instanceof Error ? reason.message : 'Could not load the backend ranking.')
      })
      .finally(() => {
        if (!controller.signal.aborted) setRankingLoading(false)
      })
    return () => controller.abort()
  }, [reloadKey])

  const sourceRows = useMemo(() => {
    if (!plan) return ranking?.vulnerabilities ?? []
    return [...plan.scheduled, ...plan.deferred].map(planRow)
  }, [plan, ranking])
  const filteredRows = useMemo(() => {
    const term = search.trim().toUpperCase()
    return sourceRows.filter((item) => item.cve_id.includes(term))
  }, [sourceRows, search])
  const visibleRows = filteredRows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)
  const totalPages = Math.max(1, Math.ceil(filteredRows.length / PAGE_SIZE))
  const missingEffort = ranking?.vulnerabilities.filter((item) => item.patch_hours === null).length ?? 0

  async function buildPlan(period: PlannerPeriod) {
    if (!ranking?.count) return
    setPlanning(true)
    setError(null)
    setPlan(null)
    try {
      const response = await createPlannerPlan({
        patchers,
        hours_per_patcher: hoursPerPatcher,
        planning_period: period,
        start_date: startDate,
        overrides: Object.entries(overrides).map(([cve_id, value]) => ({ cve_id, ...value })),
      })
      setPlan(response)
      setView('plan')
      setPage(0)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'The planning request failed.')
    } finally {
      setPlanning(false)
    }
  }

  async function exportRanking() {
    setDownloadingRanking(true)
    setError(null)
    try {
      const blob = await downloadPlannerRanking()
      saveBlob(blob, 'vesper_current_provisional_ranking.csv')
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Could not download the ranking CSV.')
    } finally {
      setDownloadingRanking(false)
    }
  }

  function reloadRanking() {
    setRanking(null)
    setPlan(null)
    setError(null)
    setRankingLoading(true)
    setReloadKey((current) => current + 1)
  }

  const selectedCount = plan?.scheduled.length ?? 0
  const periodLabel = plan?.planning_period === 'week'
    ? '5 workdays'
    : plan?.planning_period === 'month'
      ? '22 workdays'
      : '1 workday'
  const source = ranking?.vulnerabilities[0]

  return (
    <div className="mx-auto flex w-full max-w-7xl flex-col gap-5">
      <header className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div className="space-y-1">
          <p className="text-xs font-medium uppercase tracking-widest text-muted-foreground">Fusion · Risk ranking and patch planning</p>
          <h2 className="text-2xl font-semibold tracking-tight">Sprint planner</h2>
          <p className="max-w-3xl text-sm text-muted-foreground">
            Review the provisional five-signal ranking, then schedule patches within the team’s daily capacity.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" onClick={reloadRanking} disabled={rankingLoading || planning}>
            <RefreshCw aria-hidden="true" /> Reload ranking
          </Button>
          {view === 'ranking' ? (
            <Button variant="outline" onClick={exportRanking} disabled={!ranking || downloadingRanking}>
              <ArrowDownToLine aria-hidden="true" />
              {downloadingRanking ? 'Preparing CSV…' : 'Download ranking CSV'}
            </Button>
          ) : (
            <Button variant="outline" onClick={() => plan && downloadPlanCsv(plan)} disabled={!plan}>
              <ArrowDownToLine aria-hidden="true" /> Download {plan?.planning_period ?? ''} plan CSV
            </Button>
          )}
        </div>
      </header>

      {ranking && (ranking.synthetic || ranking.model_selection_status?.includes('provisional')) && (
        <div className="flex gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-sm" role="status">
          <ShieldAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
          <p>
            <strong>Provisional composite ranking.</strong> This is a normalized equal-weight score, not a trained or validated model prediction. Component snapshots are mixed-date; patch effort is estimated from CVSS severity.
          </p>
        </div>
      )}
      {error && (
        <div className="rounded-lg border border-destructive/40 bg-destructive/5 p-3 text-sm text-destructive" role="alert">
          <strong>Planner request failed.</strong> {error}
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-[minmax(17rem,0.7fr)_minmax(0,1.8fr)]">
        <div className="flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle>Ranking input</CardTitle>
              <CardDescription>Loaded by FastAPI from the current Component D output.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              {rankingLoading ? <p role="status" className="text-sm text-muted-foreground">Loading ranking…</p> : ranking ? (
                <>
                  <p className="break-all font-medium">{ranking.ranking_file}</p>
                  <p className="text-sm text-muted-foreground">
                    {ranking.count.toLocaleString()} CVEs · {ranking.ranking_model ?? 'method unspecified'}
                  </p>
                  <p className="text-xs text-muted-foreground">As of {source?.data_as_of ?? '—'}</p>
                  <p className="text-xs text-muted-foreground">
                    Text {source?.snapshot_date_a ?? '—'} · Timing {source?.snapshot_date_b ?? '—'} · Exposure {source?.snapshot_date_c ?? '—'} · CVSS {source?.baseline_snapshot_date ?? '—'} · EPSS {source?.epss_date ?? '—'}
                  </p>
                </>
              ) : <p className="text-sm text-muted-foreground">Ranking unavailable. Check FastAPI and its configured ranking CSV.</p>}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Team capacity and dates</CardTitle>
              <CardDescription>Capacity applies per workday. Weekly and monthly plans use 5 and 22 Monday–Friday workdays.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <label className="flex flex-col gap-1.5 text-sm">
                Patchers
                <input className="h-9 rounded-md border border-input bg-background px-3" type="number" min={1} max={100} step={1} value={patchers} onChange={(event) => setPatchers(Math.min(100, Math.max(1, Number(event.target.value) || 1)))} />
              </label>
              <label className="flex flex-col gap-1.5 text-sm">
                Hours per person per day
                <input className="h-9 rounded-md border border-input bg-background px-3" type="number" min={0.25} max={24} step={0.25} value={hoursPerPatcher} onChange={(event) => setHoursPerPatcher(Math.min(24, Math.max(0.25, Number(event.target.value) || 0.25)))} />
              </label>
              <label className="flex flex-col gap-1.5 text-sm">
                Plan start date
                <input className="h-9 rounded-md border border-input bg-background px-3" type="date" value={startDate} onChange={(event) => setStartDate(event.target.value)} />
              </label>
              <div className="rounded-md bg-muted p-3 text-sm">
                Daily capacity <strong>{(patchers * hoursPerPatcher).toLocaleString()} person-hours</strong>
              </div>
              <p className="text-xs text-muted-foreground">Current plan value is risk score × business criticality (defaults to 1). CVSS severity tier provides a labeled effort estimate; it is not measured patch time.</p>
              <div className="flex flex-col gap-2">
                <Button onClick={() => buildPlan('day')} disabled={!ranking || rankingLoading || planning}>{planning ? 'Planning…' : 'Build daily plan'}</Button>
                <Button variant="secondary" onClick={() => buildPlan('week')} disabled={!ranking || rankingLoading || planning}>Build weekly plan</Button>
                <Button variant="secondary" onClick={() => buildPlan('month')} disabled={!ranking || rankingLoading || planning}>Build monthly plan</Button>
              </div>
            </CardContent>
          </Card>
        </div>

        <Card className="min-w-0">
          <CardHeader className="gap-3 sm:flex-row sm:items-end sm:justify-between">
            <div className="space-y-1">
              <CardTitle>{view === 'ranking' ? 'Risk ranking' : `${plan?.planning_period ?? ''} patch plan`}</CardTitle>
              <CardDescription>
                {view === 'ranking'
                  ? 'Sorted by provisional composite score, highest first. Missing signals are excluded from each row’s mean.'
                  : plan
                    ? `${selectedCount} scheduled, ${plan.deferred.length} deferred · ${periodLabel} starting ${plan.start_date}`
                    : 'Build a plan to see scheduled and deferred CVEs.'}
              </CardDescription>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button size="sm" variant={view === 'ranking' ? 'secondary' : 'outline'} onClick={() => { setView('ranking'); setPage(0) }}>Ranking</Button>
              <Button size="sm" variant={view === 'plan' ? 'secondary' : 'outline'} onClick={() => setView('plan')} disabled={!plan}>Patch plan</Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            {view === 'plan' && plan && (
              <div className="grid gap-3 sm:grid-cols-3">
                <Card><CardContent className="pt-4"><p className="text-xs uppercase text-muted-foreground">Scheduled</p><p className="mt-1 text-xl font-semibold">{plan.scheduled.length} <span className="text-sm font-normal text-muted-foreground">CVEs</span></p></CardContent></Card>
                <Card><CardContent className="pt-4"><p className="text-xs uppercase text-muted-foreground">Effort used</p><p className="mt-1 text-xl font-semibold">{plan.used_hours.toFixed(1)} <span className="text-sm font-normal text-muted-foreground">/ {plan.capacity_hours.toFixed(1)} h</span></p></CardContent></Card>
                <Card><CardContent className="pt-4"><p className="text-xs uppercase text-muted-foreground">Missing estimates</p><p className="mt-1 text-xl font-semibold">{missingEffort} <span className="text-sm font-normal text-muted-foreground">CVEs</span></p></CardContent></Card>
              </div>
            )}
            {view === 'plan' && plan && plan.daily_summaries.length > 1 && (
              <div className="flex flex-wrap gap-2 text-xs">
                {plan.daily_summaries.map((day) => (
                  <span key={day.date} className="rounded-md border px-2 py-1">{day.date}: {day.selected_count} CVEs, {day.used_hours.toFixed(1)}/{day.capacity_hours.toFixed(1)} h</span>
                ))}
              </div>
            )}
            {(view === 'ranking' || view === 'plan') && (view === 'ranking' ? ranking : plan) && (
              <div className="flex flex-wrap items-center justify-between gap-2">
                <label className="text-sm text-muted-foreground">
                  Search CVE ID
                  <input className="ml-2 h-8 rounded-md border border-input bg-background px-2 text-foreground" type="search" value={search} onChange={(event) => { setSearch(event.target.value); setPage(0) }} placeholder="CVE-YYYY-NNNN" />
                </label>
                {view === 'plan' && <span className="text-xs text-muted-foreground">Daily knapsack is rerun on remaining CVEs for each workday.</span>}
              </div>
            )}
            {rankingLoading || planning ? (
              <p className="py-10 text-center text-sm text-muted-foreground" role="status">{rankingLoading ? 'Loading ranking…' : 'Optimizing patch schedule…'}</p>
            ) : !ranking ? (
              <p className="py-10 text-center text-sm text-muted-foreground">Load the backend ranking to start.</p>
            ) : view === 'plan' && !plan ? (
              <p className="py-10 text-center text-sm text-muted-foreground">Choose a daily, weekly, or monthly plan.</p>
            ) : filteredRows.length === 0 ? (
              <p className="py-10 text-center text-sm text-muted-foreground">No CVEs match this search.</p>
            ) : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader><TableRow>
                    {view === 'plan' && <TableHead>Status / date</TableHead>}
                    <TableHead>Risk rank</TableHead><TableHead>CVE</TableHead>
                    <TableHead className="text-right">Composite</TableHead>
                    <TableHead className="text-right">Text</TableHead><TableHead className="text-right">Exploit timing</TableHead>
                    <TableHead className="text-right">Exposure</TableHead><TableHead className="text-right">CVSS</TableHead>
                    <TableHead className="text-right">EPSS</TableHead>
                    <TableHead>Criticality</TableHead><TableHead>Patch h</TableHead>
                    {view === 'plan' && <TableHead>Plan note</TableHead>}
                  </TableRow></TableHeader>
                  <TableBody>
                    {visibleRows.map((item) => {
                      const planned = item as PlannedCandidate
                      const override = overrides[item.cve_id]
                      const patchHours = override && 'patch_hours' in override
                        ? override.patch_hours ?? null
                        : item.patch_hours
                      const criticality = override?.business_criticality ?? item.business_criticality
                      const scoreTitle = (status: string | null, reason: string | null) =>
                        [status, reason].filter(Boolean).join(': ') || undefined
                      return (
                        <TableRow key={item.cve_id}>
                          {view === 'plan' && <TableCell>{planned.selected ? `Scheduled · ${planned.planned_date ?? ''}` : 'Deferred'}</TableCell>}
                          <TableCell>{item.model_rank}</TableCell><TableCell className="font-mono">{item.cve_id}</TableCell>
                          <TableCell className="text-right font-semibold">{displayValue(item.risk_score)}</TableCell>
                          <TableCell className="text-right" title={scoreTitle(item.status_a, item.reason_a)}>{displayValue(item.score_a)}</TableCell>
                          <TableCell className="text-right" title={scoreTitle(item.status_b, item.reason_b)}>{displayValue(item.score_b)}</TableCell>
                          <TableCell className="text-right" title={scoreTitle(item.status_c, item.reason_c)}>{displayValue(item.score_c)}</TableCell>
                          <TableCell className="text-right">{displayValue(item.cvss_base_score, 1)}</TableCell>
                          <TableCell className="text-right">{displayValue(item.epss_score)}</TableCell>
                          <TableCell>
                            {view === 'ranking' ? (
                              <select
                                className="h-8 rounded-md border border-input bg-background px-2"
                                aria-label={`Business criticality for ${item.cve_id}`}
                                value={criticality}
                                onChange={(event) => setOverrides((current) => ({
                                  ...current,
                                  [item.cve_id]: { ...current[item.cve_id], business_criticality: Number(event.target.value) },
                                }))}
                              >
                                <option value={1}>1 · Low</option><option value={2}>2 · Medium</option><option value={3}>3 · High</option>
                              </select>
                            ) : criticality}
                          </TableCell>
                          <TableCell title={item.patch_hours_method ?? undefined}>
                            {view === 'ranking' ? (
                              <input
                                className="h-8 w-24 rounded-md border border-input bg-background px-2"
                                type="number"
                                min={0.25}
                                max={1000}
                                step={0.25}
                                aria-label={`Patch effort hours for ${item.cve_id}`}
                                value={patchHours ?? ''}
                                onChange={(event) => setOverrides((current) => ({
                                  ...current,
                                  [item.cve_id]: {
                                    ...current[item.cve_id],
                                    patch_hours: event.target.value === '' ? null : Number(event.target.value),
                                  },
                                }))}
                              />
                            ) : displayValue(item.patch_hours, 1)}
                          </TableCell>
                          {view === 'plan' && <TableCell className="max-w-56 whitespace-normal text-muted-foreground">{planned.reason}</TableCell>}
                        </TableRow>
                      )
                    })}
                  </TableBody>
                </Table>
              </div>
            )}
            <div className="flex items-center justify-between border-t pt-3 text-sm text-muted-foreground">
              <span>{filteredRows.length ? `${page * PAGE_SIZE + 1}–${Math.min((page + 1) * PAGE_SIZE, filteredRows.length)}` : '0'} of {filteredRows.length.toLocaleString()} CVEs</span>
              <div className="flex items-center gap-2">
                <Button size="sm" variant="outline" disabled={page === 0} onClick={() => setPage((current) => current - 1)}>Previous</Button>
                <span>{page + 1} / {totalPages}</span>
                <Button size="sm" variant="outline" disabled={page + 1 >= totalPages} onClick={() => setPage((current) => current + 1)}>Next</Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
      <p className="text-xs text-muted-foreground">
        Ranking score and schedule are distinct: the ranking orders risk signals; the planner selects the highest-value feasible tasks under each day’s estimated effort capacity. Multi-day plans run the daily optimizer in sequence and do not model dependencies, holidays, or task concurrency.
      </p>
    </div>
  )
}
