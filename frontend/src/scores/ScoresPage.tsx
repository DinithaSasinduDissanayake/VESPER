// Static help page. Owner: the whole team.
export function ScoresPage() {
  return (
    <div className="flex max-w-xl flex-col gap-2">
      <p>Each vulnerability gets three evidence scores from 0 to 100:</p>
      <ul className="list-disc pl-5">
        <li>Text: what the description says about how dangerous it is.</li>
        <li>Timing: how soon attackers are likely to exploit it.</li>
        <li>Structural relationships: structural importance derived from observed CVE–product–weakness relationships. The structural score is a PageRank percentile, not exploitation probability.</li>
      </ul>
      <p>The priority score combines these into one number. Higher means patch sooner.</p>
      <p className="text-muted-foreground">The current interface uses sample data. Raw PageRank and the complete-case CVSS comparison percentile are separate from the primary structural-score percentile.</p>
    </div>
  )
}
