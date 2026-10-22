import { useState, type FormEvent } from 'react'
import { Search } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { ExposureSection } from './ExposureSection'
import { useComponentCDetails } from './data'

export function ExposurePage() {
  const [input, setInput] = useState('')
  const [cveId, setCveId] = useState<string | null>(null)
  const [attempt, setAttempt] = useState(0)
  const [validation, setValidation] = useState<string | null>(null)
  const resource = useComponentCDetails(cveId, attempt)

  function lookup(event: FormEvent) {
    event.preventDefault()
    const normalized = input.trim().toUpperCase()
    if (!/^CVE-[0-9]{4}-[0-9]{4,}$/.test(normalized)) {
      setValidation('Enter a CVE ID in the form CVE-YYYY-NNNN.')
      return
    }
    setValidation(null)
    setCveId(normalized)
    setAttempt((value) => value + 1)
  }

  return (
    <div className="mx-auto flex max-w-6xl min-w-0 flex-col gap-5">
      <div>
        <p className="text-xs font-medium uppercase tracking-widest text-muted-foreground">Research workbench - current snapshot</p>
        <h2 className="mt-2 text-xl font-semibold tracking-tight">Explore recorded relationships</h2>
        <p className="mt-1 max-w-2xl text-sm text-muted-foreground">Look up a CVE in the configured Component C artifacts. Structural ranking, local connectivity and relationship evidence retain their own snapshot and availability.</p>
      </div>
      <form onSubmit={lookup} className="flex flex-wrap items-end gap-3 rounded-xl border bg-card p-4">
        <label className="flex min-w-0 flex-1 flex-col gap-1.5 text-xs font-medium" htmlFor="structural-cve-id">CVE ID
          <input id="structural-cve-id" value={input} onChange={(event) => setInput(event.target.value)} placeholder="CVE-YYYY-NNNN" required spellCheck={false} autoCapitalize="characters" aria-describedby="structural-lookup-help" className="min-w-0 rounded-lg border bg-background px-3 py-2 font-mono text-sm outline-none focus-visible:ring-2 focus-visible:ring-structural" />
        </label>
        <Button type="submit"><Search aria-hidden="true" />Load details</Button>
        <p id="structural-lookup-help" className="w-full text-xs text-muted-foreground">Reads saved current-snapshot results. No graph or score is recalculated.</p>
        {validation && <p role="alert" className="w-full text-sm">{validation}</p>}
      </form>
      {cveId ? <div className="space-y-3"><p className="font-mono text-sm font-medium">{cveId}</p><ExposureSection key={cveId} resource={resource} /></div> : <p className="rounded-xl border border-dashed p-8 text-center text-sm text-muted-foreground">Enter a CVE ID to inspect its structural relationships.</p>}
    </div>
  )
}
