// Plain SVG charts for the Exploit timing views (no chart library).
import { bandLabel } from './format'
import type { Band } from './types'

const WIDTH = 480
const HEIGHT = 220
const PAD = { left: 64, right: 16, top: 12, bottom: 40 }
const PLOT_W = WIDTH - PAD.left - PAD.right
const PLOT_H = HEIGHT - PAD.top - PAD.bottom

function ticks(min: number, max: number, count: number): number[] {
  return Array.from({ length: count }, (_, i) => min + ((max - min) * i) / (count - 1))
}

type LineChartProps = {
  points: [x: number, y: number][]
  xLabel: string
  yLabel: string
  yDomain: [number, number]
  formatY: (value: number) => string
  title: string
  // Shown above the plot when the y-axis does not start at 0
  zoomNote?: string
}

export function LineChart({ points, xLabel, yLabel, yDomain, formatY, title, zoomNote }: LineChartProps) {
  if (points.length < 2) return null
  const xMin = points[0][0]
  const xMax = points[points.length - 1][0]
  const [yMin, yMax] = yDomain
  const x = (value: number) => PAD.left + ((value - xMin) / (xMax - xMin || 1)) * PLOT_W
  const y = (value: number) => PAD.top + (1 - (value - yMin) / (yMax - yMin || 1)) * PLOT_H
  const path = points.map(([px, py], i) => `${i ? 'L' : 'M'}${x(px).toFixed(1)},${y(py).toFixed(1)}`).join(' ')

  return (
    <figure className="flex flex-col gap-1">
      {zoomNote && <p className="text-xs font-medium text-amber-700 dark:text-amber-400">{zoomNote}</p>}
      <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} role="img" aria-label={title} className="w-full max-w-xl">
        <title>{title}</title>
        {ticks(yMin, yMax, 5).map((value) => (
          <g key={`y${value}`}>
            <line x1={PAD.left} x2={WIDTH - PAD.right} y1={y(value)} y2={y(value)} className="stroke-border" />
            <text x={PAD.left - 6} y={y(value) + 4} textAnchor="end" className="fill-muted-foreground text-[10px]">
              {formatY(value)}
            </text>
          </g>
        ))}
        {ticks(xMin, xMax, 5).map((value) => (
          <text
            key={`x${value}`}
            x={x(value)}
            y={HEIGHT - PAD.bottom + 16}
            textAnchor="middle"
            className="fill-muted-foreground text-[10px]"
          >
            {Math.round(value)}
          </text>
        ))}
        <line x1={PAD.left} x2={PAD.left} y1={PAD.top} y2={HEIGHT - PAD.bottom} className="stroke-muted-foreground" />
        <line
          x1={PAD.left}
          x2={WIDTH - PAD.right}
          y1={HEIGHT - PAD.bottom}
          y2={HEIGHT - PAD.bottom}
          className="stroke-muted-foreground"
        />
        <path d={path} fill="none" strokeWidth={2} className="stroke-foreground" />
        <text x={PAD.left + PLOT_W / 2} y={HEIGHT - 6} textAnchor="middle" className="fill-foreground text-[11px]">
          {xLabel}
        </text>
        <text
          transform={`translate(14 ${PAD.top + PLOT_H / 2}) rotate(-90)`}
          textAnchor="middle"
          className="fill-foreground text-[11px]"
        >
          {yLabel}
        </text>
      </svg>
    </figure>
  )
}

// Baseline hazard per band, as listings per 100,000 average CVEs per day.
export function BandsChart({ bands }: { bands: Band[] }) {
  const scale = 100_000
  const max = Math.max(...bands.map((band) => band.rate_per_day * scale))
  const rowH = 28
  const labelW = 110
  const barW = WIDTH - labelW - 80
  const height = bands.length * rowH + 8

  return (
    <svg
      viewBox={`0 0 ${WIDTH} ${height}`}
      role="img"
      aria-label="Baseline hazard per age band"
      className="w-full max-w-xl"
    >
      <title>Baseline hazard per age band</title>
      {bands.map((band, i) => {
        const value = band.rate_per_day * scale
        const width = (value / max) * barW
        return (
          <g key={band.start_day} transform={`translate(0 ${i * rowH + 4})`}>
            <text x={labelW - 8} y={rowH / 2 + 4} textAnchor="end" className="fill-foreground text-[11px]">
              {bandLabel(band)}
            </text>
            <rect x={labelW} y={4} width={Math.max(width, 1)} height={rowH - 10} className="fill-foreground/70" />
            <text x={labelW + width + 6} y={rowH / 2 + 4} className="fill-muted-foreground text-[10px]">
              {value.toFixed(value < 1 ? 2 : 1)}
            </text>
          </g>
        )
      })}
    </svg>
  )
}
