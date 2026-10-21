import { useEffect, useState } from 'react'
import { ArrowDownToLine, CalendarDays, Check, Clock3, HardDrive, RefreshCw, ShieldAlert, UsersRound } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { makePlanRequest, readPlanResponse, readRankingResponse, scheduleCsv, type ApiPlanResponse, type ApiRankingResponse, type PlannerResponse, type Vulnerability } from './knapsack'
import './knapsack.css'

const PAGE_SIZE = 12

function KnapsackPlanner() {
  const [items, setItems] = useState<Vulnerability[]>([])
  const [rankingInfo, setRankingInfo] = useState<ReturnType<typeof readRankingResponse>['info'] | null>(null)
  const [patchers, setPatchers] = useState(3)
  const [hours, setHours] = useState(6)
  const [query, setQuery] = useState('')
  const [page, setPage] = useState(0)
  const [error, setError] = useState('')
  const [plan, setPlan] = useState<PlannerResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [rankingLoading, setRankingLoading] = useState(true)
  const [reloadToken, setReloadToken] = useState(0)
  const [view, setView] = useState<'top25' | 'candidates'>('top25')

  useEffect(() => {
    const controller = new AbortController()
    fetch('/api/d-fusion/ranking', { signal: controller.signal })
      .then(async (response) => {
        const body = await response.json() as ApiRankingResponse & { detail?: unknown }
        if (!response.ok) {
          const detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail ?? 'Request failed')
          throw new Error(detail)
        }
        return readRankingResponse(body)
      })
      .then((ranking) => {
        setRankingInfo(ranking.info)
        setItems(ranking.vulnerabilities)
        setPage(0)
      })
      .catch((reason: unknown) => {
        if (controller.signal.aborted) return
        setRankingInfo(null)
        setItems([])
        setError(reason instanceof Error ? reason.message : 'Could not load the backend ranking.')
      })
      .finally(() => {
        if (!controller.signal.aborted) setRankingLoading(false)
      })
    return () => controller.abort()
  }, [reloadToken])

  useEffect(() => {
    if (!items.length) return

    const controller = new AbortController()
    const timer = window.setTimeout(async () => {
      setLoading(true)
      setError('')
      try {
        const response = await fetch('/api/d-fusion/knapsack', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(makePlanRequest(items, patchers, hours)),
          signal: controller.signal,
        })
        const body = await response.json() as ApiPlanResponse & { detail?: unknown }
        if (!response.ok) {
          const detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail ?? 'Request failed')
          throw new Error(detail)
        }
        setPlan(readPlanResponse(body))
      } catch (reason) {
        if (controller.signal.aborted) return
        setPlan(null)
        setError(reason instanceof Error ? reason.message : 'The API request failed.')
      } finally {
        if (!controller.signal.aborted) setLoading(false)
      }
    }, 250)

    return () => {
      window.clearTimeout(timer)
      controller.abort()
    }
  }, [items, patchers, hours])

  const planned: (PlannerResponse['scheduled'][number])[] = plan
    ? [...plan.scheduled, ...plan.deferred].sort((left, right) => left.modelRank - right.modelRank)
    : items.map((item) => ({
      ...item,
      priorityValue: item.riskScore * item.criticality,
      selected: false,
      reason: item.patchHours === null ? 'Needs patch-time estimate' : 'Waiting for plan',
    }))
  const syntheticInput = rankingInfo?.synthetic ?? false
  const selected = plan?.scheduled ?? []
  const usedHours = plan?.usedHours ?? 0
  const totalCapacity = plan?.capacityHours ?? patchers * hours
  const needsEstimate = items.filter((item) => item.patchHours === null).length
  const allFiltered = planned.filter((item) => item.cveId.includes(query.trim().toUpperCase()))
  const displayRows = view === 'top25'
    ? selected.filter((item) => item.cveId.includes(query.trim().toUpperCase())).slice(0, 25)
    : allFiltered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)
  const pageCount = Math.max(1, Math.ceil(allFiltered.length / PAGE_SIZE))

  function updateItem(cveId: string, update: Partial<Pick<Vulnerability, 'patchHours' | 'criticality'>>) {
    setPlan(null)
    setItems((current) => current.map((item) => item.cveId === cveId ? { ...item, ...update } : item))
  }

  function updateCapacity(nextPatchers: number, nextHours: number) {
    setPlan(null)
    setPatchers(nextPatchers)
    setHours(nextHours)
  }

  function refreshRanking() {
    setRankingLoading(true)
    setLoading(false)
    setError('')
    setPlan(null)
    setRankingInfo(null)
    setItems([])
    setReloadToken((token) => token + 1)
  }

  function exportSchedule() {
    if (!plan) return
    const blob = new Blob([scheduleCsv(planned)], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = 'vesper_daily_patch_plan.csv'
    anchor.click()
    URL.revokeObjectURL(url)
  }

  return (
    <main className="planner-shell">
      <header className="planner-topbar">
        <a className="brand" href="#top" aria-label="VESPER home">
          <span className="brand-mark"><span /></span>
          <span>VESPER<span className="brand-dot">.</span></span>
        </a>
        <div className="topbar-right"><span className="status-dot" /> Component D <span className="topbar-divider">/</span> Patch planning</div>
      </header>

      <section className="planner-intro" id="top">
        <div>
          <div className="eyebrow"><span className="eyebrow-line" /> FUSION · RESOURCE ALLOCATION</div>
          <h1>Patch the risk<br /><span>you can afford today.</span></h1>
          <p className="intro-copy">Turn your vulnerability ranking into a daily patch plan that fits your team’s available time.</p>
        </div>
        <div className="intro-meta">
          <span className="meta-icon"><CalendarDays size={17} /></span>
          <div><span className="meta-label">PLANNING MODE</span><strong>One day at a time</strong></div>
          <span className="meta-divider" />
          <div><span className="meta-label">SELECTION</span><strong>0/1 knapsack</strong></div>
        </div>
      </section>

      <section className="workspace-grid">
        <aside className="controls-column">
          <Card className="planner-card source-card">
            <CardContent className="card-pad">
              <div className="section-heading"><span className="step-number">01</span><div><h2>Backend ranking</h2><p>Loaded from Component D output</p></div></div>
              <div className={`ranking-source ${items.length ? 'has-file' : ''}`}>
                <span className="upload-icon">{items.length ? <Check size={19} /> : <HardDrive size={18} />}</span>
                <span className="upload-text"><strong>{rankingInfo?.rankingFile ?? (rankingLoading ? 'Loading ranking…' : 'Ranking unavailable')}</strong><small>{rankingInfo ? `${rankingInfo.count.toLocaleString()} CVEs · ${rankingInfo.rankingModel ?? 'model unspecified'}` : 'Expected at outputs/d_fusion/ranked_vulnerabilities.csv'}</small></span>
                <Button className="refresh-button" variant="ghost" size="icon" aria-label="Reload backend ranking" onClick={refreshRanking} disabled={rankingLoading}><RefreshCw size={15} /></Button>
              </div>
              <p className="field-hint">FastAPI selects this file on the server. Refresh after regenerating the ranking.</p>
              {error && <p className="error-message" role="alert">{error}</p>}
            </CardContent>
          </Card>

          <Card className="planner-card capacity-card">
            <CardContent className="card-pad">
              <div className="section-heading"><span className="step-number">02</span><div><h2>Team capacity</h2><p>Available patching time for today</p></div></div>
              <div className="input-pair">
                <label className="number-field"><span><UsersRound size={15} /> PATCHERS</span><div><input type="number" min="1" max="100" value={patchers} onChange={(event) => updateCapacity(Math.max(1, Math.min(100, Number(event.target.value) || 1)), hours)} /><small>people</small></div></label>
                <label className="number-field"><span><Clock3 size={15} /> HOURS / PERSON</span><div><input type="number" min="0.25" max="24" step="0.25" value={hours} onChange={(event) => updateCapacity(patchers, Math.max(0.25, Math.min(24, Number(event.target.value) || 0.25)))} /><small>hours</small></div></label>
              </div>
              <div className="capacity-summary"><span>Daily team capacity</span><strong>{totalCapacity.toLocaleString()} <small>person-hours</small></strong></div>
            </CardContent>
          </Card>

          <Card className="planner-card method-card">
            <CardContent className="card-pad">
              <div className="section-heading"><span className="step-number">03</span><div><h2>Impact &amp; selection</h2><p>Set per-CVE values in the table</p></div></div>
              <div className="method-equation"><span>Priority value</span><strong>Risk score × criticality</strong><small>Criticality: 1 low · 2 medium · 3 high</small></div>
              <div className="method-note"><ShieldAlert size={15} /><span>Heuristic planning value, not a predicted loss reduction.</span></div>
            </CardContent>
          </Card>
        </aside>

        <section className="results-column">
          <div className="metrics-row">
            <Card className="metric-card metric-highlight"><CardContent><span>SELECTED TODAY</span><strong>{selected.length}<small> CVEs</small></strong><div className="metric-caption"><Check size={13} /> Fits within team capacity</div></CardContent></Card>
            <Card className="metric-card"><CardContent><span>PATCH TIME ALLOCATED</span><strong>{usedHours.toFixed(1)}<small> / {totalCapacity} h</small></strong><div className="meter"><span style={{ width: `${totalCapacity ? Math.min(100, usedHours / totalCapacity * 100) : 0}%` }} /></div></CardContent></Card>
            <Card className="metric-card"><CardContent><span>NEEDS ESTIMATE</span><strong>{planned.filter((item) => item.patchHours === null).length || items.filter((item) => item.patchHours === null).length}<small> CVEs</small></strong><div className="metric-caption muted-caption">Not included until estimated</div></CardContent></Card>
          </div>

          {syntheticInput && <div className="provenance-notice"><ShieldAlert size={15} /><span><strong>Synthetic ranking input.</strong> This schedule demonstrates the workflow; it is not a validated operational risk plan.</span></div>}
          {error && <div className="api-error" role="alert"><ShieldAlert size={15} /><span><strong>Planner request failed.</strong> {error} Check the FastAPI service and ranking file.</span></div>}

          <Card className="planner-card ranking-card">
            <div className="ranking-header">
              <div><div className="table-kicker">DAILY DECISION QUEUE {loading && <span className="loading-label">· CALCULATING</span>}</div><h2>Patch schedule <span>{plan ? `${selected.length} selected` : rankingLoading ? 'Loading ranking' : 'Waiting for schedule'}</span></h2></div>
              <div className="table-actions">
                <label className="search-box"><span>⌕</span><input aria-label="Search CVE ID" placeholder="Search CVE" value={query} onChange={(event) => { setQuery(event.target.value); setPage(0) }} /></label>
                <Button className="export-button" onClick={exportSchedule} disabled={!plan}><ArrowDownToLine size={15} /> Export full CSV</Button>
              </div>
            </div>
            <div className="schedule-tabs"><button className={view === 'top25' ? 'active' : ''} type="button" onClick={() => setView('top25')}>Top 25 selected <span>{Math.min(selected.length, 25)}</span></button><button className={view === 'candidates' ? 'active' : ''} type="button" onClick={() => setView('candidates')}>All candidates &amp; inputs <span>{items.length.toLocaleString()}</span></button></div>
            {rankingLoading ? <div className="empty-state"><span className="empty-icon"><RefreshCw size={21} /></span><strong>Loading the backend ranking</strong><p>FastAPI is reading the configured Component D CSV.</p></div> : items.length ? (
              displayRows.length ? <div className="table-scroll"><table className="ranking-table"><thead><tr><th>STATUS</th><th>VULNERABILITY</th><th>RISK</th><th>CRITICALITY</th><th>PATCH EFFORT</th><th>PRIORITY VALUE</th><th>PLAN NOTE</th></tr></thead><tbody>
                {displayRows.map((item) => <tr key={item.cveId} className={item.selected ? 'row-selected' : ''}>
                  <td><span className={`decision-pill ${item.selected ? 'is-selected' : ''}`}><i />{item.selected ? 'TODAY' : 'DEFERRED'}</span></td>
                  <td><strong className="cve-id">{item.cveId}</strong><small className="model-rank">Model rank #{item.modelRank}</small></td>
                  <td><span className="risk-value">{item.riskScore.toFixed(3)}</span><div className="risk-track"><span style={{ width: `${item.riskScore * 100}%` }} /></div></td>
                  <td><select aria-label={`Business criticality for ${item.cveId}`} value={item.criticality} onChange={(event) => updateItem(item.cveId, { criticality: Number(event.target.value) })}><option value={1}>1 · Low</option><option value={2}>2 · Medium</option><option value={3}>3 · High</option></select></td>
                  <td><label className="effort-input"><input aria-label={`Patch hours for ${item.cveId}`} type="number" min="0.25" max="1000" step="0.25" placeholder="Add hours" value={item.patchHours ?? ''} onChange={(event) => updateItem(item.cveId, { patchHours: event.target.value === '' ? null : Math.max(0.25, Number(event.target.value)) })} /><span>h</span></label></td>
                  <td className="priority-number">{item.priorityValue.toFixed(3)}</td><td className="reason-cell">{item.reason}</td>
                </tr>)}
              </tbody></table></div> : <div className="empty-state"><span className="empty-icon"><HardDrive size={23} /></span><strong>{view === 'top25' ? 'No CVEs selected for today yet' : 'No CVEs match your search'}</strong><p>{view === 'top25' ? `Add patch estimates in All candidates & inputs. ${needsEstimate.toLocaleString()} CVEs currently need estimates.` : 'Try another CVE ID search.'}</p>{view === 'top25' && <Button variant="outline" onClick={() => setView('candidates')}>Enter candidate estimates</Button>}</div>
            ) : <div className="empty-state"><span className="empty-icon"><HardDrive size={23} /></span><strong>Backend ranking unavailable</strong><p>{error || 'Generate outputs/d_fusion/ranked_vulnerabilities.csv, then reload the ranking.'}</p><Button variant="outline" onClick={refreshRanking} disabled={rankingLoading}><RefreshCw size={15} /> Retry</Button></div>}
            {items.length > 0 && view === 'candidates' && <div className="table-footer"><span>Showing {allFiltered.length ? page * PAGE_SIZE + 1 : 0}–{Math.min((page + 1) * PAGE_SIZE, allFiltered.length)} of {allFiltered.length.toLocaleString()} CVEs</span><div><button type="button" disabled={page === 0} onClick={() => setPage((current) => current - 1)}>Previous</button><span>{page + 1} / {pageCount}</span><button type="button" disabled={page + 1 >= pageCount} onClick={() => setPage((current) => current + 1)}>Next</button></div></div>}
          </Card>
          <p className="planner-footnote">The planner treats patch tasks as independent and patchers as interchangeable. Effort is rounded up to 15-minute increments so the plan never exceeds capacity.</p>
        </section>
      </section>
      <footer className="planner-footer"><span>VESPER <b>·</b> Vulnerability prioritisation research</span><span>Component D <b>·</b> Provisional planning heuristic</span></footer>
    </main>
  )
}

export default KnapsackPlanner
