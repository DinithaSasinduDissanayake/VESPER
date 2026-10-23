// Owner: D.S. Dissanayake — Analyse a new CVE: paste a description, get the
// text model's ranking score and the words behind it (Component A).
import { useEffect, useRef, useState } from 'react'
import { CircleAlert, LoaderCircle, ServerOff, WifiOff } from 'lucide-react'
import {
  ApiUnreachableError,
  getTextModel,
  MAX_TEXT_LENGTH,
  ModelUnavailableError,
  scoreText,
  type TextModelInfo,
  type TextScore,
} from '@/api/aText'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { Textarea } from '@/components/ui/textarea'
import { examples } from './examples'
import { Explanation } from './Explanation'
import { ScoreResult } from './ScoreResult'

type State =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'done'; result: TextScore; text: string }
  | { kind: 'error'; error: unknown }

// A short headline for the two known 503 messages from api/a_text.py.
function unavailableTitle(message: string) {
  if (message.includes('masking rules changed')) return 'Masking rules changed since training: retrain the text model'
  if (message.includes('not found')) return 'The text model has not been trained yet'
  return 'The text model is not available'
}

function ErrorAlert({ error }: { error: unknown }) {
  if (error instanceof ModelUnavailableError) {
    return (
      <Alert variant="destructive">
        <ServerOff />
        <AlertTitle>{unavailableTitle(error.message)}</AlertTitle>
        <AlertDescription>
          <p>Nothing was scored. The server said:</p>
          <p className="font-mono text-sm break-all">{error.message}</p>
        </AlertDescription>
      </Alert>
    )
  }
  if (error instanceof ApiUnreachableError) {
    return (
      <Alert variant="destructive">
        <WifiOff />
        <AlertTitle>Cannot reach the VESPER API</AlertTitle>
        <AlertDescription>Check that the backend is running, then try again.</AlertDescription>
      </Alert>
    )
  }
  return (
    <Alert variant="destructive">
      <CircleAlert />
      <AlertTitle>Something went wrong</AlertTitle>
      <AlertDescription>{error instanceof Error ? error.message : String(error)}</AlertDescription>
    </Alert>
  )
}

function EmptyState() {
  return (
    <Card className="border-dashed bg-transparent shadow-none">
      <CardContent className="flex flex-col gap-1 text-muted-foreground">
        <p className="font-medium text-foreground">No result yet</p>
        <p>
          Paste a description and press Analyse, or try an example. You will see a ranking score, the words that
          pushed it up or down, and the text the model actually read after leak wording was removed.
        </p>
      </CardContent>
    </Card>
  )
}

export function AnalysePage() {
  const [text, setText] = useState('')
  const [state, setState] = useState<State>({ kind: 'idle' })
  const [model, setModel] = useState<TextModelInfo | null>(null)
  const request = useRef<AbortController | null>(null)

  // Model metadata for the header; a 503 here is shown before anyone types.
  useEffect(() => {
    let live = true
    getTextModel()
      .then((info) => live && setModel(info))
      .catch((error) => {
        if (live && error instanceof ModelUnavailableError) setState({ kind: 'error', error })
      })
    return () => {
      live = false
      request.current?.abort()
    }
  }, [])

  async function analyse(value: string) {
    if (value.trim() === '') return
    request.current?.abort() // only the latest click counts
    const controller = new AbortController()
    request.current = controller
    setState({ kind: 'loading' })
    try {
      const result = await scoreText(value, controller.signal)
      setState({ kind: 'done', result, text: value })
    } catch (error) {
      if (!controller.signal.aborted) setState({ kind: 'error', error })
    }
  }

  const empty = text.trim() === ''
  const loading = state.kind === 'loading'

  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle>Paste a vulnerability description</CardTitle>
          <CardDescription>
            The text model ranks how likely a CVE is to enter CISA KEV, using the description alone. Wording that
            gives the answer away is removed before scoring.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <Textarea
            aria-label="Vulnerability description"
            placeholder="e.g. A buffer overflow in the web interface of … allows a remote attacker to …"
            value={text}
            maxLength={MAX_TEXT_LENGTH}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) analyse(text)
            }}
            className="min-h-32"
          />
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm text-muted-foreground">Try an example:</span>
            {examples.map((example) => (
              <Button
                key={example.label}
                variant="outline"
                size="sm"
                disabled={loading}
                onClick={() => {
                  setText(example.text)
                  analyse(example.text)
                }}
              >
                {example.label}
              </Button>
            ))}
          </div>
        </CardContent>
        <CardFooter className="flex-wrap justify-between gap-3">
          <span className="text-sm text-muted-foreground">
            {model
              ? `Model ${model.model_version}, trained on CVEs up to ${model.trained_through}`
              : 'Ctrl+Enter also analyses.'}
          </span>
          <Button disabled={empty || loading} onClick={() => analyse(text)}>
            {loading && <LoaderCircle data-icon="inline-start" className="animate-spin" />}
            Analyse
          </Button>
        </CardFooter>
      </Card>

      {state.kind === 'idle' && <EmptyState />}
      {state.kind === 'error' && <ErrorAlert error={state.error} />}
      {loading && (
        <p role="status" className="flex items-center gap-2 text-muted-foreground">
          <LoaderCircle className="size-4 animate-spin" /> Scoring the description…
        </p>
      )}
      {state.kind === 'done' && (
        <div
          className={
            state.result.status === 'available' ? 'grid items-start gap-6 lg:grid-cols-[20rem_1fr]' : 'max-w-2xl'
          }
        >
          <ScoreResult result={state.result} />
          <Explanation result={state.result} original={state.text} />
        </div>
      )}
    </div>
  )
}
