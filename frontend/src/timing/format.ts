// Small formatting helpers for the Exploit timing views.
import type { Band } from './types'

export function day(iso: string): string {
  return iso.slice(0, 10)
}

export function percentText(value: number, digits = 2): string {
  return `${(value * 100).toFixed(digits)}%`
}

// Y-axis range around the values, so small changes near 1 are visible.
export function zoomedDomain(values: number[]): [number, number] {
  const min = Math.min(...values)
  const max = Math.max(...values)
  const spread = max - min || 1e-6
  return [Math.max(0, min - spread * 0.1), Math.min(1, max + spread * 0.1)]
}

export function bandLabel(band: Band): string {
  return band.end_day === null ? `${band.start_day}+ days` : `${band.start_day}–${band.end_day} days`
}

// "Apache Karaf (Apache Software Foundation)", or the start of the description.
export function whatItIs(detail: { product: string | null; vendor: string | null; description: string | null }): string {
  if (detail.product) return detail.vendor ? `${detail.product} (${detail.vendor})` : detail.product
  return detail.description ?? '—'
}

// The exact 30-day number, for example "0.601%".
export function chanceText(value: number | null): string {
  return value === null ? '—' : `${(value * 100).toFixed(3)}%`
}
