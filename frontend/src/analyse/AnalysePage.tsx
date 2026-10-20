// Owner: D.S. Dissanayake — build this page here.
// Starter form only. Nothing is sent anywhere yet.
export function AnalysePage() {
  return (
    <form className="flex max-w-xl flex-col gap-3" onSubmit={(e) => e.preventDefault()}>
      <label className="flex flex-col gap-1">
        CVE ID or description
        <textarea rows={4} className="rounded-md border px-2 py-1" />
      </label>
      <button
        type="submit"
        disabled
        className="self-start rounded-md border px-3 py-1 text-muted-foreground"
      >
        Analyse
      </button>
      <p className="text-muted-foreground">Analysis service not connected yet.</p>
    </form>
  )
}
