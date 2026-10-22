import { useEffect, useState } from 'react'
import type { TimingData } from './types'

// The demo file written by the Python export. There is no backend API yet.
export const TIMING_DATA_URL = '/demo/exploit_timing.json'
export const REGENERATE_COMMAND = 'uv run python -m vesper.components.b_survival.frontend_export'

export type TimingState =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'ready'; data: TimingData }

// Loaded once and shared by every page and card.
let request: Promise<TimingData> | null = null

export function loadTimingData(): Promise<TimingData> {
  request ??= fetch(TIMING_DATA_URL).then(async (response) => {
    if (!response.ok) throw new Error(`${TIMING_DATA_URL} not found (HTTP ${response.status})`)
    try {
      return (await response.json()) as TimingData
    } catch {
      throw new Error(`${TIMING_DATA_URL} is not valid JSON`)
    }
  })
  // A failed request is not cached, so a later visit can try again.
  request.catch(() => {
    request = null
  })
  return request
}

export function useTimingData(): TimingState {
  const [state, setState] = useState<TimingState>({ status: 'loading' })
  useEffect(() => {
    let active = true
    loadTimingData().then(
      (data) => active && setState({ status: 'ready', data }),
      (error: unknown) =>
        active && setState({ status: 'error', message: error instanceof Error ? error.message : String(error) }),
    )
    return () => {
      active = false
    }
  }, [])
  return state
}
