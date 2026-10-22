import { useState } from 'react'
import { ExposureSection } from './ExposureSection'
import { demoScenarios, sampleStructuralState, type DemoScenario } from './sampleStructuralDetails'
export function ExposurePage() {
  const [scenario, setScenario] = useState<DemoScenario>('higher')
  return (
    <div className="mx-auto flex max-w-6xl min-w-0 flex-col gap-5">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div><p className="text-xs font-medium uppercase tracking-widest text-muted-foreground">Research workbench · sample data</p><h2 className="mt-2 text-xl font-semibold tracking-tight">Explore recorded relationships</h2><p className="mt-1 max-w-xl text-sm text-muted-foreground">A closer look at structural importance, relationship evidence and CVSS comparison. No live API is connected.</p></div>
        <label className="flex min-w-0 flex-col gap-1.5 text-xs font-medium">Demo scenario<select value={scenario} onChange={(event) => setScenario(event.target.value as DemoScenario)} className="max-w-full rounded-lg border bg-background px-3 py-2 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring">{demoScenarios.map(({ value, label }) => <option key={value} value={value}>{label}</option>)}</select></label>
      </div>
      <ExposureSection key={scenario} resource={sampleStructuralState(scenario)} />
    </div>
  )
}
