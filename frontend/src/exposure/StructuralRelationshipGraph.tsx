import { useId, useState } from 'react'
import { Building2, Fingerprint, Package, Tag } from 'lucide-react'
import { cn } from '@/lib/utils'
import { toPercent } from '@/queue/format'
import type { StructuralDetails } from './types'

type GraphNode = { id: string; kind: 'vendor' | 'product' | 'cve' | 'cwe' | 'summary'; label: string; context: string; x: number; y: number }
type GraphEdge = { from: string; to: string }
const icons = { vendor: Building2, product: Package, cve: Fingerprint, cwe: Tag, summary: Package }
const WIDTH = 174
const HEIGHT = 70

function GraphArrow({ connected, active }: { connected: string[]; active: string | null }) {
  const emphasized = active !== null && connected.includes(active)
  return <svg className={cn('mx-auto h-7 w-4', emphasized ? 'text-structural' : 'text-muted-foreground/50')} viewBox="0 0 16 28" aria-hidden="true"><path d="M8 0v24m-4-4 4 4 4-4" fill="none" stroke="currentColor" strokeWidth={emphasized ? 2.5 : 1.5} /></svg>
}

export function StructuralRelationshipGraph({ data }: { data: StructuralDetails }) {
  const id = useId().replaceAll(':', '')
  const [hovered, setHovered] = useState<string | null>(null)
  const [focused, setFocused] = useState<string | null>(null)
  const active = hovered ?? focused
  const products = data.relationships.vendorProducts
  const weaknesses = data.relationships.cweIds
  const preview = products.values.slice(0, 4)
  const vendors = [...new Set(preview.map((p) => p.vendor))]
  const rows = Math.max(preview.length, weaknesses.values.slice(0, 4).length, 2)
  const height = rows * 92 + 140
  const centerY = height / 2 - HEIGHT / 2
  const place = (index: number, count: number) => height / 2 + (index - (count - 1) / 2) * 92 - HEIGHT / 2
  const nodes: GraphNode[] = [
    ...vendors.map((vendor, i) => ({ id: `vendor-${i}`, kind: 'vendor' as const, label: vendor, context: 'Recorded vendor', x: 14, y: place(i, vendors.length) })),
    ...preview.map((pair, i) => ({ id: `product-${i}`, kind: 'product' as const, label: pair.product, context: pair.vendor, x: 234, y: place(i, preview.length) })),
    { id: 'cve', kind: 'cve', label: data.cveId, context: 'Selected vulnerability', x: 494, y: centerY },
    ...weaknesses.values.slice(0, 4).map((cwe, i) => ({ id: `cwe-${i}`, kind: 'cwe' as const, label: cwe, context: 'Recorded weakness', x: 754, y: place(i, Math.min(4, weaknesses.values.length)) })),
  ]
  const edges: GraphEdge[] = [
    ...preview.flatMap((pair, i) => [{ from: `vendor-${vendors.indexOf(pair.vendor)}`, to: `product-${i}` }, { from: `product-${i}`, to: 'cve' }]),
    ...weaknesses.values.slice(0, 4).map((_, i) => ({ from: 'cve', to: `cwe-${i}` })),
  ]
  if (products.values.length > 4) nodes.push({ id: 'more-products', kind: 'summary', label: `+${products.values.length - 4} more products`, context: 'See full evidence below', x: 234, y: height - HEIGHT - 3 })
  if (weaknesses.values.length > 4) nodes.push({ id: 'more-cwes', kind: 'summary', label: `+${weaknesses.values.length - 4} more weaknesses`, context: 'See full evidence below', x: 754, y: height - HEIGHT - 3 })

  function nodeButton(node: GraphNode) {
    const Icon = icons[node.kind]
    const isCve = node.kind === 'cve'
    const context = isCve
      ? `${node.context}${data.structuralScore.status === 'available' && data.structuralScore.value !== null ? ` · ${toPercent(data.structuralScore.value)}% PageRank percentile` : ''}${data.graphFeatures.degree !== null ? ` · Degree ${data.graphFeatures.degree}` : ''}`
      : node.context
    return (
      <button type="button"
        aria-label={`${node.kind === 'summary' ? '' : `${node.kind}: `}${node.label}. ${context}`}
        onMouseEnter={() => setHovered(node.id)} onMouseLeave={() => setHovered(null)}
        onFocus={() => setFocused(node.id)} onBlur={() => setFocused(null)}
        className={cn('flex h-full w-full min-w-0 flex-col justify-center rounded-xl border px-3 py-2 text-left outline-none focus-visible:ring-2 focus-visible:ring-structural focus-visible:ring-offset-2 focus-visible:ring-offset-background',
          isCve ? 'border-2 border-structural-border bg-structural-node text-structural-node-foreground shadow-sm' : 'border-border bg-background text-foreground',
          node.kind === 'vendor' && 'border-dashed bg-muted/60',
          node.kind === 'product' && 'border-structural-border/40 bg-structural-soft',
          node.kind === 'cwe' && 'rounded-2xl border-structural-border/40 bg-structural-soft/60',
          node.kind === 'summary' && 'border-dashed text-muted-foreground',
          active === node.id && !isCve && 'border-structural ring-1 ring-structural')}
        title={`${node.label} · ${context}`}>
        <span className="flex min-w-0 items-center gap-2 text-sm font-semibold"><Icon className="size-4 shrink-0" aria-hidden="true" /><span className="truncate">{node.label}</span></span>
        <span className={cn('mt-1 block truncate text-xs', isCve ? 'text-structural-node-foreground/80' : 'text-muted-foreground')}>{node.context}</span>
      </button>
    )
  }

  return (
    <section className="min-w-0 overflow-hidden rounded-xl border" aria-labelledby={`${id}-title`}>
      <div className="flex flex-wrap items-center justify-between gap-3 border-b px-5 py-4">
        <div><h4 id={`${id}-title`} className="font-semibold">Observed relationship graph</h4><p className="mt-1 text-sm text-muted-foreground">Vendor → Product → CVE → CWE</p></div>
        <span className="rounded-full border px-2.5 py-1 text-xs font-medium uppercase tracking-wider">Local evidence preview</span>
      </div>
      <div className="bg-muted/20 p-3 sm:p-5">
        <div className="hidden xl:block">
          <div className="grid grid-cols-4 text-center text-xs font-medium uppercase tracking-widest text-muted-foreground" aria-hidden="true"><span>Vendors</span><span>Products</span><span>Vulnerability</span><span>Weaknesses</span></div>
          <svg viewBox={`0 0 948 ${height}`} className="block w-full overflow-visible" role="group" aria-label={`Recorded relationships for ${data.cveId}`}>
            <defs><marker id={`${id}-arrow`} markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0 0 7 3.5 0 7" fill="currentColor" /></marker></defs>
            {edges.map((edge) => {
              const source = nodes.find((n) => n.id === edge.from)!
              const target = nodes.find((n) => n.id === edge.to)!
              const x1 = source.x + WIDTH + (source.kind === 'cve' ? 10 : 2), y1 = source.y + HEIGHT / 2
              const x2 = target.x - (target.kind === 'cve' ? 15 : 7), y2 = target.y + HEIGHT / 2
              const emphasized = active === source.id || active === target.id
              return <path key={`${edge.from}-${edge.to}`} d={`M${x1},${y1} C${(x1 + x2) / 2},${y1} ${(x1 + x2) / 2},${y2} ${x2},${y2}`} fill="none" stroke="currentColor" strokeWidth={emphasized ? 2.5 : 1.2} className={emphasized ? 'text-structural' : 'text-muted-foreground/40'} markerEnd={`url(#${id}-arrow)`} />
            })}
            {nodes.map((node) => <foreignObject key={node.id} x={node.x - (node.kind === 'cve' ? 8 : 0)} y={node.y - (node.kind === 'cve' ? 8 : 0)} width={WIDTH + (node.kind === 'cve' ? 16 : 0)} height={HEIGHT + (node.kind === 'cve' ? 16 : 0)}>{nodeButton(node)}</foreignObject>)}
          </svg>
        </div>
        <div className="space-y-1 xl:hidden" role="group" aria-label={`Recorded relationships for ${data.cveId}`}>
          <div className="grid gap-3 sm:grid-cols-2">
            {preview.map((pair, i) => <div key={`${pair.vendor}:${pair.product}`} className="min-w-0 rounded-xl border border-dashed p-3"><div className="h-[70px]">{nodeButton(nodes.find((n) => n.id === `vendor-${vendors.indexOf(pair.vendor)}`)!)}</div><GraphArrow active={active} connected={[`vendor-${vendors.indexOf(pair.vendor)}`, `product-${i}`]} /><div className="h-[70px]">{nodeButton(nodes.find((n) => n.id === `product-${i}`)!)}</div></div>)}
          </div>
          {products.values.length > 4 && <p className="py-2 text-center text-sm text-muted-foreground">+{products.values.length - 4} more products · full evidence below</p>}
          {preview.length > 0 && <GraphArrow active={active} connected={['cve', ...preview.map((_, i) => `product-${i}`)]} />}
          <div className="mx-auto h-[86px] max-w-xs">{nodeButton(nodes.find((n) => n.id === 'cve')!)}</div>
          {weaknesses.values.length > 0 && <GraphArrow active={active} connected={['cve', ...weaknesses.values.slice(0, 4).map((_, i) => `cwe-${i}`)]} />}
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">{nodes.filter((n) => n.kind === 'cwe').map((node) => <div key={node.id} className="h-[70px] min-w-0">{nodeButton(node)}</div>)}</div>
          {weaknesses.values.length > 4 && <p className="py-2 text-center text-sm text-muted-foreground">+{weaknesses.values.length - 4} more weaknesses · full evidence below</p>}
        </div>
        {(products.status !== 'supported' || weaknesses.status !== 'supported') && <p className="mt-3 rounded-lg border border-dashed bg-background p-3 text-sm text-muted-foreground">{products.status !== 'supported' && `Product evidence ${products.status.replaceAll('_', ' ')}. `}{weaknesses.status !== 'supported' && `Weakness evidence ${weaknesses.status.replaceAll('_', ' ')}. `}Missing evidence is not a confirmed empty relationship set.</p>}
      </div>
      <div className="space-y-2 border-t px-5 py-4">
        <p className="flex flex-wrap gap-x-4 gap-y-1 text-sm font-medium"><span>{products.status === 'supported' ? `${products.values.length} affected-product relationships` : 'Product count unavailable'}</span><span>{weaknesses.status === 'supported' ? `${weaknesses.values.length} weakness relationships` : 'Weakness count unavailable'}</span><span>Degree {data.graphFeatures.degree ?? 'unavailable'}</span></p>
        <p className="text-sm leading-relaxed text-muted-foreground">Edges represent recorded vendor, product and weakness relationships — not network attack paths. Preview shows up to four products and four weaknesses. Hover or focus a node to emphasize its connections.</p>
      </div>
    </section>
  )
}
