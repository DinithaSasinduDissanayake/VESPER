import assert from 'node:assert/strict'
import { after, test } from 'node:test'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { createServer } from 'vite'

// Uses the existing Vite/React dependencies; no test framework installation.
const server = await createServer({ server: { middlewareMode: true }, appType: 'custom' })
after(() => server.close())
const { ExposureSection } = await server.ssrLoadModule('/src/exposure/ExposureSection.tsx')
const { StructuralSummary } = await server.ssrLoadModule('/src/exposure/StructuralSummary.tsx')
const { StructuralRelationshipGraph } = await server.ssrLoadModule('/src/exposure/StructuralRelationshipGraph.tsx')
const { sampleStructuralState, sampleStructuralDetails, structuralStateForQueueItem } = await server.ssrLoadModule('/src/exposure/sampleStructuralDetails.ts')
const { sampleQueue } = await server.ssrLoadModule('/src/queue/sampleQueue.ts')
const render = (Component, props) => renderToStaticMarkup(createElement(Component, props))
const panel = (scenario) => render(ExposureSection, { resource: sampleStructuralState(scenario) })

test('sample panel separates primary percentile, raw PageRank and comparison cohort', () => {
  const html = panel('higher')
  for (const text of ['Sample / demo data', '97%', '4.280e-5', '94%', '76%', '+18.0', 'not validated research results', 'not exploitation probability']) assert.ok(html.includes(text), text)
})

test('unavailable score preserves supported product evidence without fabricated zeros', () => {
  const html = panel('unavailable')
  assert.ok(html.includes('Unavailable'))
  assert.ok(html.includes('Comparison unavailable'))
  assert.ok(html.includes('document_processor'))
  assert.ok(html.includes('Weakness count unavailable'))
  assert.ok(!html.includes('role="meter"'))
  assert.ok(!html.includes('>0%<'))
  assert.ok(!html.includes('>0<'))
})

test('not eligible never displays a score or claims evaluated relationships', () => {
  const html = panel('not_eligible')
  assert.ok(html.includes('not eligible'))
  assert.ok(html.includes('not evaluated'))
  assert.ok(!html.includes('97%'))
  assert.ok(!html.includes('document_processor'))
})

test('a legitimate zero remains distinct from missing data', () => {
  const data = sampleStructuralDetails('CVE-2026-10001', 0)
  data.graphFeatures = { degree: 0, pagerankRaw: 0 }
  const html = render(StructuralSummary, { data })
  assert.ok(html.includes('0%'))
  assert.ok(html.includes('0.000e+0'))
  assert.ok(!html.includes('Unavailable'))
})

test('comparison has higher, equal and lower interpretation states', () => {
  assert.ok(panel('higher').includes('Structural ranking higher than CVSS'))
  assert.ok(panel('similar').includes('Similar structural and CVSS ranking'))
  assert.ok(panel('lower').includes('Structural ranking lower than CVSS'))
})

test('loading and error states contain no stale score or graph', () => {
  const loading = panel('loading'), error = panel('error')
  assert.ok(loading.includes('role="status"'))
  assert.ok(error.includes('role="alert"'))
  for (const html of [loading, error]) {
    assert.ok(!html.includes('97%'))
    assert.ok(!html.includes('<foreignObject'))
  }
})

test('large graph preview is bounded and gives access to complete evidence', () => {
  const data = sampleStructuralDetails('CVE-2026-10001')
  data.relationships.vendorProducts.values = Array.from({ length: 200 }, (_, i) => ({ vendor: 'demo', product: `sample_product_${i}` }))
  data.relationships.cweIds.values = Array.from({ length: 200 }, (_, i) => `CWE-${i + 1}`)
  const html = render(StructuralRelationshipGraph, { data })
  assert.ok(html.includes('+196 more products'))
  assert.ok(html.includes('+196 more weaknesses'))
  assert.ok(!html.includes('sample_product_199'))
  assert.ok((html.match(/<foreignObject/g) ?? []).length < 16)
  assert.ok(html.includes('aria-label="product: sample_product_0'))
})

test('queue detail fixtures keep the selected CVE and score state', () => {
  for (const item of sampleQueue) {
    const resource = structuralStateForQueueItem(item)
    assert.equal(resource.state, 'loaded')
    assert.equal(resource.data.cveId, item.vulnerability.cve_id)
    const score = item.scores.find((s) => s.component === 'c_graph')
    assert.equal(resource.data.structuralScore.value, score?.score ?? null)
    assert.equal(resource.data.structuralScore.status, score?.status ?? 'unavailable')
  }
})

test('missing C artifacts show a calm note without configuration jargon', () => {
  const message = 'Component C artifacts unavailable. Configure VESPER_C_FEATURE_PROVIDER_CSV, VESPER_C_SCORES_CSV and their metadata sidecars; disagreement CSV is optional.'
  const html = render(ExposureSection, { resource: { state: 'error', message } })
  assert.ok(html.includes('Structural details not loaded on this machine'))
  assert.ok(!html.includes('VESPER_C_'))
  assert.ok(!html.includes('role="alert"'))
})
