import assert from 'node:assert/strict'
import { after, afterEach, test } from 'node:test'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { createServer } from 'vite'

const server = await createServer({ server: { middlewareMode: true }, appType: 'custom' })
after(() => server.close())
const { requestComponentCDetails, mapComponentCDetails } = await server.ssrLoadModule('/src/exposure/data.ts')
const { ExposureSection } = await server.ssrLoadModule('/src/exposure/ExposureSection.tsx')
const originalFetch = globalThis.fetch
afterEach(() => { globalThis.fetch = originalFetch })
const cveId = 'CVE-2024-12345'

function apiResponse() {
  return {
    cve_id: cveId, structural_score: 0.97, score_kind: 'ranking_score',
    score_status: 'available', score_reason: null, raw_pagerank: 0.0000428, degree: 7,
    pagerank_comparison_percentile: 0.94, cvss_percentile: 0.76,
    pagerank_cvss_disagreement: 0.18, comparison_status: 'available', comparison_reason: null,
    scoring_population: 1000, comparison_population: 800,
    vendor_product_relationships: [{ vendor: 'fixture_vendor', product: 'fixture_product' }],
    cwe_ids: ['CWE-79'], cpe_evidence_status: 'supported', cpe_evidence_reason: null,
    cwe_evidence_status: 'supported', cwe_evidence_reason: null,
    snapshot_date: '2026-10-15', reference_time: '2026-10-15T00:00:00Z',
    model_version: 'c_graph-pagerank-percentile-structural-0.2',
    provenance: {
      snapshot_id: 'nvd-current-snapshot-2026-10-15', graph_scope_id: 'graph-test',
      feature_schema_version: '1.0.0', provider_model_version: 'c_graph-pagerank-structural-0.1',
      source_record_published_at: '2024-01-01T00:00:00Z',
      source_record_last_modified_at: '2026-10-15T00:00:00Z', source_nvd_file: 'fixture.json.gz',
      feature_provenance: 'saved_current_snapshot_graph_and_local_nvd_record',
      provider_sha256: 'a'.repeat(64), scores_sha256: 'b'.repeat(64), analysis_sha256: 'c'.repeat(64),
    },
  }
}

const markup = (resource) => renderToStaticMarkup(createElement(ExposureSection, { resource }))

test('real API boundary publishes loading then loaded, maps all three values separately', async () => {
  let url, signal
  globalThis.fetch = async (input, options) => {
    url = input; signal = options.signal
    return new Response(JSON.stringify(apiResponse()))
  }
  const controller = new AbortController(), states = []
  await requestComponentCDetails(cveId, controller.signal, (state) => states.push(state))
  assert.equal(url, `/api/c-graph/cves/${cveId}`)
  assert.equal(signal, controller.signal)
  assert.deepEqual(states.map((s) => s.state), ['loading', 'loaded'])
  const data = states[1].data
  assert.equal(data.dataSource, 'api')
  assert.equal(data.structuralScore.value, 0.97)
  assert.equal(data.graphFeatures.pagerankRaw, 0.0000428)
  assert.equal(data.cvssComparison.structuralPercentile, 0.94)
  assert.equal(data.graphFeatures.degree, 7)
  const html = markup(states[1])
  for (const text of ['97%', '4.280e-5', '94%', '76%', '+18.0', 'fixture_product', 'CWE-79', 'graph-test']) assert.ok(html.includes(text), text)
  assert.ok(!html.includes('Sample / demo data'))
  assert.ok(!html.includes('document_processor'))
})

test('in-flight request displays loading without stale sample measurements', async () => {
  let resolve
  globalThis.fetch = () => new Promise((done) => { resolve = done })
  const states = [], controller = new AbortController()
  const pending = requestComponentCDetails(cveId, controller.signal, (state) => states.push(state))
  assert.equal(states[0].state, 'loading')
  assert.ok(markup(states[0]).includes('role="status"'))
  assert.ok(!markup(states[0]).includes('97%'))
  resolve(new Response(JSON.stringify(apiResponse())))
  await pending
})

test('HTTP error stays an error and never falls back to fixtures', async () => {
  globalThis.fetch = async () => new Response(JSON.stringify({ detail: 'Configure C artifacts first.' }), { status: 503 })
  const states = []
  await requestComponentCDetails(cveId, new AbortController().signal, (state) => states.push(state))
  assert.deepEqual(states.map((s) => s.state), ['loading', 'error'])
  const html = markup(states[1])
  assert.ok(html.includes('Configure C artifacts first.'))
  assert.ok(html.includes('role="alert"'))
  assert.ok(!html.includes('97%'))
  assert.ok(!html.includes('<foreignObject'))
})

test('unavailable API values stay null while supported product evidence remains', () => {
  const response = apiResponse()
  Object.assign(response, {
    structural_score: null, raw_pagerank: null, degree: null,
    score_status: 'abstained', score_reason: 'No graph feature row.',
    pagerank_comparison_percentile: null, cvss_percentile: null, pagerank_cvss_disagreement: null,
    comparison_status: 'unavailable', comparison_reason: 'No compatible comparison.',
    cwe_ids: [], cwe_evidence_status: 'unavailable', cwe_evidence_reason: 'Weakness evidence unavailable.',
  })
  const data = mapComponentCDetails(response)
  assert.equal(data.structuralScore.value, null)
  const html = markup({ state: 'loaded', data })
  assert.ok(html.includes('Comparison unavailable'))
  assert.ok(html.includes('fixture_product'))
  assert.ok(!html.includes('>0%<'))
  assert.ok(!html.includes('role="meter"'))
})

test('valid zero API score is preserved and rendered as zero percent', () => {
  const response = apiResponse(); response.structural_score = 0
  const data = mapComponentCDetails(response)
  assert.equal(data.structuralScore.value, 0)
  assert.ok(markup({ state: 'loaded', data }).includes('0%'))
})

test('malformed or mismatched successful API response becomes error, not fixtures', async () => {
  for (const changed of [{ cve_id: 'CVE-2024-99999' }, { structural_score: null }, { raw_pagerank: '0.5' }, { pagerank_cvss_disagreement: 0.5 }]) {
    globalThis.fetch = async () => new Response(JSON.stringify({ ...apiResponse(), ...changed }))
    const states = []
    await requestComponentCDetails(cveId, new AbortController().signal, (state) => states.push(state))
    assert.deepEqual(states.map((s) => s.state), ['loading', 'error'])
  }
})

test('an aborted request cannot publish stale data or a false error', async () => {
  let resolve
  globalThis.fetch = () => new Promise((done) => { resolve = done })
  const controller = new AbortController(), states = []
  const pending = requestComponentCDetails(cveId, controller.signal, (state) => states.push(state))
  controller.abort()
  resolve(new Response(JSON.stringify(apiResponse())))
  await pending
  assert.deepEqual(states.map((s) => s.state), ['loading'])
})

test('no optional analysis keeps Degree and comparison unavailable', () => {
  const response = apiResponse()
  Object.assign(response, {
    degree: null, pagerank_comparison_percentile: null, cvss_percentile: null,
    pagerank_cvss_disagreement: null, comparison_status: 'unavailable',
    comparison_reason: 'Disagreement analysis is not configured.', comparison_population: null,
  })
  const data = mapComponentCDetails(response)
  assert.equal(data.graphFeatures.degree, null)
  assert.equal(data.cvssComparison.available, false)
})
