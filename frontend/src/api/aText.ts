// Component A (text signal) API: score one pasted description.
// Backend: src/vesper/api/a_text.py and components/a_text/score.py (score_description).

export type WordContribution = {
  term: string // a word or word pair the model read
  contribution: number // this term's share of the log-odds (+ pushes up, - pushes down)
  spans: [start: number, end: number][] // where it appears in the ORIGINAL pasted text
}

export type TextScore = {
  status: 'available' | 'abstained'
  reason: string | null // gate reason, e.g. security_cue, too_short, recipe_without_...
  score_kind: 'ranking_score'
  ranking_score: number | null // 0-1, keeps the order; NOT a probability
  log_odds: number | null
  uncalibrated_probability: number | null // not shown: it is not calibrated
  model_version: string
  trained_through: string
  horizon_days: number
  model_text: string | null // the masked text the model actually read
  top_words: { up: WordContribution[]; down: WordContribution[] }
  // These four add up to log_odds.
  totals: { words: number; char_ngrams: number; intercept: number; offset: number } | null
}

export type TextModelInfo = {
  model_version: string
  trained_through: string
  horizon_days: number
  n_train: number
  n_positives: number
  trained_at: string | null
}

export const MAX_TEXT_LENGTH = 10_000 // ScoreRequest.text max_length

// 503: the model file is missing, or the masking rules changed since training.
export class ModelUnavailableError extends Error {}
// No answer from the backend (fetch failed, or the dev proxy could not connect).
export class ApiUnreachableError extends Error {}

async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(url, init)
  } catch (error) {
    if (init?.signal?.aborted) throw error
    throw new ApiUnreachableError('No response from the VESPER API.')
  }
  const body = await response.json().catch(() => null)
  if (response.status === 503) {
    throw new ModelUnavailableError(body?.detail ?? 'The text model is not available.')
  }
  // The Vite proxy answers 500/502/504 with no JSON body when the backend is down.
  if (!body && [500, 502, 504].includes(response.status)) {
    throw new ApiUnreachableError(`The API proxy answered ${response.status}.`)
  }
  if (!response.ok) {
    const detail = typeof body?.detail === 'string' ? body.detail : `Request failed (${response.status})`
    throw new Error(detail)
  }
  return body as T
}

export function scoreText(text: string, signal?: AbortSignal): Promise<TextScore> {
  return requestJson('/api/a-text/score', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text }),
    signal,
  })
}

// One shared request: the app's idle warm-up and the Analyse page use the same answer.
// A failure is not kept, so the next caller tries again.
let modelInfo: Promise<TextModelInfo> | null = null

export function getTextModel(): Promise<TextModelInfo> {
  modelInfo ??= requestJson<TextModelInfo>('/api/a-text/model').catch((error) => {
    modelInfo = null
    throw error
  })
  return modelInfo
}

// Called once after the app shell renders: the first request loads the model into the
// backend's memory, so the first Analyse click is fast. Silent on any failure.
export function warmUpTextModel() {
  const run = () => void getTextModel().catch(() => {})
  if ('requestIdleCallback' in window) window.requestIdleCallback(run, { timeout: 2000 })
  else setTimeout(run, 2000)
}
