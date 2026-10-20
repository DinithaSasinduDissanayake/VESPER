import { useEffect, useMemo, useState } from 'react'
import { ArrowDownToLine, RefreshCw, ShieldAlert } from 'lucide-react'
import {
  createPlannerPlan,
  getPlannerRanking,
  type PlannedCandidate,
  type PlannerCandidate,
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

const PAGE_SIZE = 15
type View = 'top25' | 'candidates'

function downloadCsv(rows: PlannedCandidate[]) {
  const quote = (value: string | number) => `"${String(value).replaceAll('"', '""')}"`
  const columns = [
    'cve_id',
    'model_rank',
    'risk_score',
    'business_criticality',
    'priority_value',
    'patch_hours',
    'scheduled_today',
    'status',
  ]
  const lines = rows.map((item) =>
    [
      item.cve_id,
      item.model_rank,
      item.risk_score.toFixed(5),
      item.business_criticality,
      item.priority_value.toFixed(5),
      item.patch_hours ?? '',
      item.selected ? 'yes' : 'no',
      item.reason,
    ].map(quote).join(','),
  )
  const blob = new Blob([[columns.map(quote).join(','), ...lines].join('\r\n')], {
    type: 'text/csv;charset=utf-8',
  })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = 'vesper_daily_patch_plan.csv'
  link.click()
  URL.revokeObjectURL(url)
}

function displayPlanRows(plan: PlannerResponse): PlannedCandidate[] {
  return [...plan.scheduled, ...plan.deferred].sort((left, right) => left.model_rank - right.model_rank)
}

function initialPlanRow(item: PlannerCandidate): PlannedCandidate {
  return {
    ...item,
    priority_value: item.risk_score * item.business_criticality,
    selected: false,
    reason: item.patch_hours === null ? 'Needs patch-time estimate' : 'Plan not generated',
  }
}

export function SprintPlanPage() {
  const [ranking, setRanking] = useState<PlannerRanking | null>(null)
  const [candidates, setCandidates] = useState<PlannerCandidate[]>([])
  const [patchers, setPatchers] = useState(3)
  const [hoursPerPatcher, setHoursPerPatcher] = useState(6)
  const [view, setView] = useState<View>('top25')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(0)
  const [plan, setPlan] = useState<PlannerResponse | null>(null)
  const [rankingLoading, setRankingLoading] = useState(true)
  const [planning, setPlanning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [reloadKey, setReloadKey] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    getPlannerRanking(controller.signal)
      .then((response) => {
        setRanking(response)
        setCandidates(response.vulnerabilities)
        setPlan(null)
        setPage(0)
      })
      .catch((reason: unknown) => {
        if (controller.signal.aborted) return
        setRanking(null)
        setCandidates([])
        setError(reason instanceof Error ? reason.message : 'Could not load the backend ranking.')
      })
      .finally(() => {
        if (!controller.signal.aborted) setRankingLoading(false)
      })
    return () => controller.abort()
  }, [reloadKey])

  const planRows = useMemo(
    () => plan ? displayPlanRows(plan) : candidates.map(initialPlanRow),
    [candidates, plan],
  )
  const filteredRows = useMemo(() => {
    const term = search.trim().toUpperCase()
    return planRows.filter((item) => item.cve_id.includes(term))
  }, [planRows, search])
  const selected = plan?.scheduled ?? []
  const rows = view === 'top25'
    ? selected
      .filter((item) => item.cve_id.includes(search.trim().toUpperCase()))
      .sort((left, right) => left.model_rank - right.model_rank)
      .slice(0, 25)
    : filteredRows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)
  const totalPages = Math.max(1, Math.ceil(filteredRows.length / PAGE_SIZE))
  const capacity = plan?.capacity_hours ?? patchers * hoursPerPatcher
  const missingEffort = candidates.filter((item) => item.patch_hours === null).length

  function updateCandidate(cveId: string, update: Partial<Pick<PlannerCandidate, 'patch_hours' | 'business_criticality'>>) {
    setPlan(null)
    setCandidates((current) => current.map((item) =>
      item.cve_id === cveId ? { ...item, ...update } : item,
    ))
  }

  function updateCapacity(update: { patchers?: number; hours?: number }) {
    setPlan(null)
    if (update.patchers !== undefined) setPatchers(update.patchers)
    if (update.hours !== undefined) setHoursPerPatcher(update.hours)
  }

  async function buildPlan() {
    if (!candidates.length) return
    setPlanning(true)
    setError(null)
    setPlan(null)
    try {
      const response = await createPlannerPlan({
        patchers,
        hours_per_patcher: hoursPerPatcher,
        overrides: candidates.map((item) => ({
          cve_id: item.cve_id,
          patch_hours: item.patch_hours,
          business_criticality: item.business_criticality,
        })),
      })
      setPlan(response)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'The planning request failed.')
    } finally {
      setPlanning(false)
    }
  }

  function refreshRanking() {
    setPlan(null)
    setRanking(null)
    setCandidates([])
    setError(null)
    setRankingLoading(true)
    setReloadKey((current) => current + 1)
  }

  const exportRows = plan ? displayPlanRows(plan) : []

  return (
    <div className="mx-auto flex w-full max-w-7xl flex-col gap-5">
      <header className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div className="space-y-1">
          <p className="text-xs font-medium uppercase tracking-widest text-muted-foreground">Fusion · Resource allocation</p>
          <h2 className="text-2xl font-semibold tracking-tight">Daily sprint plan</h2>
          <p className="max-w-2xl text-sm text-muted-foreground">
            Select the fixes with the highest risk and business priority that fit your team’s available patching time.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" onClick={refreshRanking} disabled={rankingLoading}>
            <RefreshCw aria-hidden="true" /> Reload ranking
          </Button>
          <Button onClick={buildPlan} disabled={!candidates.length || rankingLoading || planning}>
            {planning ? 'Building plan…' : 'Build daily plan'}
          </Button>
        </div>
      </header>

      {ranking?.synthetic && (
        <div className="flex gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-sm" role="status">
          <ShieldAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
          <p><strong>Synthetic ranking input.</strong> This plan demonstrates the workflow; it is not a validated operational risk plan.</p>
        </div>
      )}
      {error && (
        <div className="rounded-lg border border-destructive/40 bg-destructive/5 p-3 text-sm text-destructive" role="alert">
          <strong>Planner request failed.</strong> {error}
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-[minmax(17rem,0.8fr)_minmax(0,1.7fr)]">
        <div className="flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle>Backend ranking</CardTitle>
              <CardDescription>Loaded by FastAPI from the configured Component D ranking CSV.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              {rankingLoading ? <p className="text-sm text-muted-foreground" role="status">Loading ranking…</p> : ranking ? (
                <>
                  <p className="break-all font-medium">{ranking.ranking_file}</p>
                  <p className="text-sm text-muted-foreground">
                    {ranking.count.toLocaleString()} CVEs · {ranking.ranking_model ?? 'model unspecified'}
                  </p>
                  {ranking.model_selection_status && <p className="text-xs text-muted-foreground">{ranking.model_selection_status}</p>}
                </>
              ) : <p className="text-sm text-muted-foreground">Ranking unavailable. Check that FastAPI is running and the ranking CSV exists.</p>}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Team capacity</CardTitle>
              <CardDescription>Available patching time for one day.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <label className="flex flex-col gap-1.5 text-sm">
                Patchers
                <input
                  className="h-9 rounded-md border border-input bg-background px-3"
                  type="number"
                  min={1}
                  max={100}
                  step={1}
                  value={patchers}
                  onChange={(event) => updateCapacity({ patchers: Math.min(100, Math.max(1, Number(event.target.value) || 1)) })}
                />
              </label>
              <label className="flex flex-col gap-1.5 text-sm">
                Hours per person
                <input
                  className="h-9 rounded-md border border-input bg-background px-3"
                  type="number"
                  min={0.25}
                  max={24}
                  step={0.25}
                  value={hoursPerPatcher}
                  onChange={(event) => updateCapacity({ hours: Math.min(24, Math.max(0.25, Number(event.target.value) || 0.25)) })}
                />
              </label>
              <div className="rounded-md bg-muted p-3 text-sm">
                Daily capacity <strong>{capacity.toLocaleString()} person-hours</strong>
              </div>
              <p className="text-xs text-muted-foreground">Selection value is risk score × business criticality (1 low, 2 medium, 3 high).</p>
            </CardContent>
          </Card>
        </div>

        <div className="flex min-w-0 flex-col gap-4">
          <div className="grid gap-4 sm:grid-cols-3">
            <Card><CardContent className="pt-4"><p className="text-xs uppercase text-muted-foreground">Selected today</p><p className="mt-1 text-2xl font-semibold">{selected.length}<span className="ml-1 text-sm font-normal text-muted-foreground">CVEs</span></p></CardContent></Card>
            <Card><CardContent className="pt-4"><p className="text-xs uppercase text-muted-foreground">Patch time allocated</p><p className="mt-1 text-2xl font-semibold">{(plan?.used_hours ?? 0).toFixed(1)}<span className="ml-1 text-sm font-normal text-muted-foreground">/ {capacity} h</span></p></CardContent></Card>
            <Card><CardContent className="pt-4"><p className="text-xs uppercase text-muted-foreground">Needs effort estimate</p><p className="mt-1 text-2xl font-semibold">{missingEffort}<span className="ml-1 text-sm font-normal text-muted-foreground">CVEs</span></p></CardContent></Card>
          </div>

          <Card className="min-w-0">
            <CardHeader className="gap-3 sm:flex-row sm:items-end sm:justify-between">
              <div className="space-y-1">
                <CardTitle>Patch schedule</CardTitle>
                <CardDescription>
                  {plan ? `${selected.length} scheduled, ${plan.deferred.length} deferred` : 'Build a plan to see scheduled and deferred CVEs.'}
                </CardDescription>
              </div>
              <div className="flex flex-wrap gap-2">
                <Button size="sm" variant={view === 'top25' ? 'secondary' : 'outline'} onClick={() => setView('top25')}>Top 25 selected</Button>
                <Button size="sm" variant={view === 'candidates' ? 'secondary' : 'outline'} onClick={() => { setView('candidates'); setPage(0) }}>All candidates &amp; inputs</Button>
                <Button size="sm" variant="outline" onClick={() => downloadCsv(exportRows)} disabled={!plan}>
                  <ArrowDownToLine aria-hidden="true" /> Export full CSV
                </Button>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              {view === 'candidates' && (
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <label className="text-sm text-muted-foreground">
                    Search CVE ID
                    <input
                      className="ml-2 h-8 rounded-md border border-input bg-background px-2 text-foreground"
                      type="search"
                      value={search}
                      onChange={(event) => { setSearch(event.target.value); setPage(0) }}
                      placeholder="CVE-YYYY-NNNN"
                    />
                  </label>
                  <span className="text-xs text-muted-foreground">Patch estimates are planner inputs; blank estimates are excluded.</span>
                </div>
              )}

              {rankingLoading || planning ? (
                <p className="py-10 text-center text-sm text-muted-foreground" role="status">
                  {rankingLoading ? 'Loading the backend ranking…' : 'Calculating the daily plan…'}
                </p>
              ) : !ranking ? (
                <p className="py-10 text-center text-sm text-muted-foreground">Load a ranking to start planning.</p>
              ) : view === 'top25' && !plan ? (
                <p className="py-10 text-center text-sm text-muted-foreground">Set patch estimates under “All candidates &amp; inputs”, then build the daily plan.</p>
              ) : rows.length === 0 ? (
                <p className="py-10 text-center text-sm text-muted-foreground">
                  {view === 'top25' ? 'No CVEs are scheduled yet. Add patch estimates and build a plan.' : 'No candidates match this search.'}
                </p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Status</TableHead>
                      <TableHead>CVE / rank</TableHead>
                      <TableHead className="text-right">Risk</TableHead>
                      <TableHead>Criticality</TableHead>
                      <TableHead>Patch hours</TableHead>
                      <TableHead>Priority value</TableHead>
                      <TableHead>Plan note</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rows.map((item) => (
                      <TableRow key={item.cve_id}>
                        <TableCell>{item.selected ? 'Today' : plan ? 'Deferred' : '—'}</TableCell>
                        <TableCell className="font-mono">{item.cve_id}<span className="block font-sans text-xs text-muted-foreground">Rank #{item.model_rank}</span></TableCell>
                        <TableCell className="text-right">{item.risk_score.toFixed(3)}</TableCell>
                        <TableCell>
                          {view === 'candidates' ? (
                            <select
                              className="h-8 rounded-md border border-input bg-background px-2"
                              aria-label={`Business criticality for ${item.cve_id}`}
                              value={item.business_criticality}
                              onChange={(event) => updateCandidate(item.cve_id, { business_criticality: Number(event.target.value) })}
                            >
                              <option value={1}>1 · Low</option><option value={2}>2 · Medium</option><option value={3}>3 · High</option>
                            </select>
                          ) : item.business_criticality}
                        </TableCell>
                        <TableCell>
                          {view === 'candidates' ? (
                            <input
                              className="h-8 w-28 rounded-md border border-input bg-background px-2"
                              type="number"
                              min={0.25}
                              max={1000}
                              step={0.25}
                              aria-label={`Patch hours for ${item.cve_id}`}
                              placeholder="Add hours"
                              value={item.patch_hours ?? ''}
                              onChange={(event) => updateCandidate(item.cve_id, {
                                patch_hours: event.target.value === '' ? null : Number(event.target.value),
                              })}
                            />
                          ) : item.patch_hours === null ? '—' : `${item.patch_hours} h`}
                        </TableCell>
                        <TableCell>{item.priority_value.toFixed(3)}</TableCell>
                        <TableCell className="max-w-56 whitespace-normal text-muted-foreground">{item.reason}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}

              {view === 'candidates' && ranking && (
                <div className="flex items-center justify-between border-t pt-3 text-sm text-muted-foreground">
                  <span>{filteredRows.length ? `${page * PAGE_SIZE + 1}–${Math.min((page + 1) * PAGE_SIZE, filteredRows.length)}` : '0'} of {filteredRows.length.toLocaleString()} candidates</span>
                  <div className="flex items-center gap-2">
                    <Button size="sm" variant="outline" disabled={page === 0} onClick={() => setPage((current) => current - 1)}>Previous</Button>
                    <span>{page + 1} / {totalPages}</span>
                    <Button size="sm" variant="outline" disabled={page + 1 >= totalPages} onClick={() => setPage((current) => current + 1)}>Next</Button>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
          <p className="text-xs text-muted-foreground">
            The planner treats patch tasks as independent and patchers as interchangeable. Effort and business criticality are user-provided or ranking-file values; the priority value is a planning heuristic, not a predicted loss reduction.
          </p>
        </div>
      </div>
    </div>
  )
}
