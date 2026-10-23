// Why the text got its score: highlighted words, top word lists, the log-odds
// breakdown and the masked text the model read.
import { ChevronDown } from 'lucide-react'
import type { TextScore, WordContribution } from '@/api/aText'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { Separator } from '@/components/ui/separator'
import { cn } from '@/lib/utils'

// Red pushes towards KEV (more risk), blue away from it, as in common model explainers.
const UP = 'bg-rose-500/20 text-rose-950 dark:text-rose-100'
const DOWN = 'bg-sky-500/20 text-sky-950 dark:text-sky-100'
const UP_BAR = 'bg-rose-500'
const DOWN_BAR = 'bg-sky-500'

function signed(value: number, digits = 3): string {
  return `${value >= 0 ? '+' : '−'}${Math.abs(value).toFixed(digits)}`
}

// Split the original text into plain and highlighted pieces. Where terms overlap
// (a word pair and one of its words), the larger contribution wins.
function highlightPieces(text: string, words: WordContribution[]) {
  const owner: (WordContribution | null)[] = new Array(text.length).fill(null)
  const bySize = [...words].sort((a, b) => Math.abs(a.contribution) - Math.abs(b.contribution))
  for (const word of bySize) {
    for (const [start, end] of word.spans) owner.fill(word, start, end)
  }
  const pieces: { text: string; word: WordContribution | null }[] = []
  for (let i = 0; i < text.length; i++) {
    const last = pieces.at(-1)
    if (last && last.word === owner[i]) last.text += text[i]
    else pieces.push({ text: text[i], word: owner[i] })
  }
  return pieces
}

function HighlightedText({ text, words }: { text: string; words: WordContribution[] }) {
  return (
    <p className="max-w-[80ch] leading-8">
      {highlightPieces(text, words).map((piece, i) =>
        piece.word ? (
          <mark
            key={i}
            title={`${piece.word.term}: ${signed(piece.word.contribution)}`}
            className={cn('rounded-sm', piece.word.contribution > 0 ? UP : DOWN)}
          >
            {piece.text}
          </mark>
        ) : (
          <span key={i}>{piece.text}</span>
        ),
      )}
    </p>
  )
}

function WordList({ title, words, max }: { title: string; words: WordContribution[]; max: number }) {
  return (
    <div className="flex min-w-0 flex-col gap-2">
      <h3 className="font-medium">{title}</h3>
      {words.length === 0 && <p className="text-sm text-muted-foreground">None.</p>}
      <ol className="flex flex-col gap-1.5">
        {words.map((word) => (
          <li key={word.term} className="grid grid-cols-[1fr_4rem_4rem] items-center gap-3 text-sm">
            <span className="truncate">{word.term}</span>
            <span className="h-1.5 rounded-full bg-muted">
              <span
                className={cn('block h-full rounded-full', word.contribution > 0 ? UP_BAR : DOWN_BAR)}
                style={{ width: `${(Math.abs(word.contribution) / max) * 100}%` }}
              />
            </span>
            <span className="text-right tabular-nums text-muted-foreground">{signed(word.contribution)}</span>
          </li>
        ))}
      </ol>
    </div>
  )
}

// One row per part of the log-odds, as a bar left (down) or right (up) of zero.
function Breakdown({ totals, logOdds }: { totals: NonNullable<TextScore['totals']>; logOdds: number }) {
  const rows = [
    { label: 'Readable words', value: totals.words },
    { label: 'Character patterns', value: totals.char_ngrams },
    { label: 'Base level (intercept + offset)', value: totals.intercept + totals.offset },
  ]
  const max = Math.max(...rows.map((row) => Math.abs(row.value)), Math.abs(logOdds))
  // Share of the text's own push (words + fragments) that comes from fragments.
  const textPush = Math.abs(totals.words) + Math.abs(totals.char_ngrams)
  const charShare = textPush > 0 ? Math.abs(totals.char_ngrams) / textPush : 0
  return (
    <div className="flex flex-col gap-2">
      {[...rows, { label: 'Log-odds (the sum)', value: logOdds }].map((row, i) => (
        <div
          key={row.label}
          className={cn('grid grid-cols-[14rem_1fr_4.5rem] items-center gap-3 text-sm', i === 3 && 'font-medium')}
        >
          <span>{row.label}</span>
          <span className="relative h-3 rounded-sm bg-muted">
            <span className="absolute inset-y-0 left-1/2 w-px bg-border" />
            <span
              className={cn('absolute inset-y-0', row.value >= 0 ? `left-1/2 ${UP_BAR}` : `right-1/2 ${DOWN_BAR}`)}
              style={{ width: `${(Math.abs(row.value) / max) * 50}%` }}
            />
          </span>
          <span className="text-right tabular-nums">{signed(row.value, 2)}</span>
        </div>
      ))}
      <p className="text-sm text-muted-foreground">
        Honest caveat: character patterns (short letter fragments, too many to list) carry{' '}
        {Math.round(charShare * 100)}% of what the text contributes here, so the word lists above explain only
        part of the score.
      </p>
    </div>
  )
}

function ModelText({ original, modelText }: { original: string; modelText: string }) {
  const masked = original.replace(/\s+/g, ' ').trim() !== modelText
  return (
    <Collapsible defaultOpen={masked} className="flex flex-col gap-2">
      <CollapsibleTrigger asChild>
        <Button variant="ghost" className="group/model self-start px-2">
          <ChevronDown data-icon="inline-start" className="transition-transform group-data-[state=closed]/model:-rotate-90" />
          What the model saw
          <Badge variant={masked ? 'secondary' : 'outline'}>{masked ? 'leak wording removed' : 'nothing masked'}</Badge>
        </Button>
      </CollapsibleTrigger>
      <CollapsibleContent className="flex flex-col gap-2">
        <p className="max-w-[80ch] rounded-lg bg-muted px-3 py-2 font-mono text-sm leading-6">{modelText}</p>
        <p className="text-sm text-muted-foreground">
          Words that only appear after a CVE is attacked (exploited, KEV, proof-of-concept, links and IDs, patch
          notes) are deleted before scoring, so the score cannot read the answer from the text.
        </p>
      </CollapsibleContent>
    </Collapsible>
  )
}

export function Explanation({ result, original }: { result: TextScore; original: string }) {
  if (result.status !== 'available' || !result.totals || result.log_odds === null) return null
  const { up, down } = result.top_words
  const max = Math.max(1e-9, ...[...up, ...down].map((word) => Math.abs(word.contribution)))
  return (
    <Card>
      <CardHeader>
        <CardTitle>Why this score</CardTitle>
        <CardDescription>
          Words the model links with KEV entry, not proof of what causes attacks.{' '}
          <mark className={cn('rounded px-1', UP)}>Red</mark> pushes the score up,{' '}
          <mark className={cn('rounded px-1', DOWN)}>blue</mark> pushes it down. Hover a word for its share.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-6">
        <HighlightedText text={original} words={[...up, ...down]} />
        <div className="grid gap-6 md:grid-cols-2">
          <WordList title="Pushes the score up" words={up} max={max} />
          <WordList title="Pushes the score down" words={down} max={max} />
        </div>
        <Separator />
        <div className="flex flex-col gap-3">
          <h3 className="font-medium">Where the log-odds come from</h3>
          <Breakdown totals={result.totals} logOdds={result.log_odds} />
        </div>
        <Separator />
        {result.model_text && <ModelText original={original} modelText={result.model_text} />}
      </CardContent>
    </Card>
  )
}
