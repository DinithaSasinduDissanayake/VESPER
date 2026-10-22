// Static help page. Owner: the whole team.
export function ScoresPage() {
  return (
    <div className="flex max-w-2xl flex-col gap-4 leading-relaxed">
      <h2 className="text-lg font-semibold">How the evidence fits together</h2>
      <p>The current provisional ranking combines available text, timing, structural, CVSS and EPSS signals. It is not a trained or validated predictive model. The patch planner uses this existing ranking and estimated effort; the browser does not recompute fusion.</p>
      <section className="space-y-2 rounded-xl border bg-card p-5">
        <h3 className="font-semibold">Structural Relationships</h3>
        <p>Vulnerability relationships form a Vendor ? Product ? CVE ? CWE graph.</p>
        <p>Degree measures direct/local connectivity. PageRank measures broader structural prominence. The D-facing structural score is a PageRank-based percentile ranking.</p>
        <p>A score of <strong>0.97</strong> means this CVE ranks above approximately 97% of the Component C scoring population according to PageRank. It does not mean a 97% probability of exploitation. Tied values share ranks.</p>
        <p className="text-muted-foreground">Raw PageRank is separate from the primary structural percentile. Structural?CVSS comparisons use a separate complete-case cohort. Missing scores remain unavailable, while an actual score of zero remains valid.</p>
        <p className="text-muted-foreground">These are recorded vulnerability associations, not an organization's network or attack paths. Snapshot identity and evidence status accompany each result.</p>
      </section>
      <p className="text-muted-foreground">Data sources differ: ranking and structural details come from backend artifacts; Exploit timing reads its separately exported model file. Demo fixtures are not a fallback for unavailable structural data.</p>
    </div>
  )
}
