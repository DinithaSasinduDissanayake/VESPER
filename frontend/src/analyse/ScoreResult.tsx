// The result card: the ranking score, or why the text was not scored.
import { ShieldCheck } from 'lucide-react'
import type { TextScore } from '@/api/aText'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'

// Plain words for each gate reason (text_gate.py and score.py).
const reasonText: Record<string, { title: string; detail: string }> = {
  missing_text: { title: 'No text to score', detail: 'Paste a vulnerability description first.' },
  too_short: {
    title: 'Too short to score',
    detail: 'A description needs at least 3 words. Paste the full text.',
  },
  too_short_after_masking: {
    title: 'Too little left after masking',
    detail: 'Almost everything was leak wording, links or IDs, so nothing useful was left to score.',
  },
  recipe_without_software_or_security_context: {
    title: 'This is a recipe, not a vulnerability description',
    detail: 'It reads like cooking instructions and mentions no software or security terms.',
  },
  ordinary_prose_without_software_or_security_context: {
    title: 'This is not a vulnerability description',
    detail: 'It reads like everyday prose and mentions no software or security terms.',
  },
}

function ModelFooter({ result }: { result: TextScore }) {
  return (
    <CardFooter className="flex-wrap gap-x-4 gap-y-1 text-sm text-muted-foreground">
      <span>Model {result.model_version}</span>
      <span>Trained through {result.trained_through}</span>
    </CardFooter>
  )
}

export function ScoreResult({ result }: { result: TextScore }) {
  if (result.status === 'abstained' || result.ranking_score === null) {
    const reason = reasonText[result.reason ?? ''] ?? {
      title: 'Not scored',
      detail: 'The model declined to score this text.',
    }
    return (
      <Card>
        <CardHeader>
          <CardTitle>Not scored, on purpose</CardTitle>
          <CardDescription>
            The model refuses text it was not built for instead of inventing a number for it.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <Alert className="border-stream-text/40 bg-stream-text/5">
            <ShieldCheck className="text-stream-text" />
            <AlertTitle>{reason.title}</AlertTitle>
            <AlertDescription>{reason.detail}</AlertDescription>
          </Alert>
          <p className="text-sm text-muted-foreground">
            A plain text classifier would give any input a confident-looking score. This scope check is part of
            the model, so a refusal is the correct answer here.
          </p>
          <p className="flex items-center gap-2 text-sm text-muted-foreground">
            Reason code <Badge variant="outline">{result.reason}</Badge>
          </p>
        </CardContent>
        <ModelFooter result={result} />
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Ranking score</CardTitle>
        <CardDescription>
          Ranking score, not a probability. Higher = more likely to enter CISA KEV within {result.horizon_days}{' '}
          days.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <p className="text-5xl font-semibold tracking-tight tabular-nums">{result.ranking_score.toFixed(2)}</p>
        <Progress
          value={result.ranking_score * 100}
          aria-label="Ranking score"
          className="h-2 *:data-[slot=progress-indicator]:bg-stream-text"
        />
        <p className="text-sm text-muted-foreground">
          0.5 is a typical CVE (the middle of held-out training scores). Use it to compare and sort CVEs.
        </p>
        {result.reason === 'uncertain_scope_retained' && (
          <p className="text-sm text-muted-foreground">
            The text has no clear security or software words. It was scored anyway, so read it with care.
          </p>
        )}
      </CardContent>
      <ModelFooter result={result} />
    </Card>
  )
}
