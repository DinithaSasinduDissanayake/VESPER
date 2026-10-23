import assert from 'node:assert/strict'
import { after, test } from 'node:test'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { createServer } from 'vite'

// Same approach as exposure/*.test.mjs: render with Vite's SSR loader, no extra framework.
const server = await createServer({ server: { middlewareMode: true }, appType: 'custom' })
after(() => server.close())
const { ScoreResult } = await server.ssrLoadModule('/src/analyse/ScoreResult.tsx')
const { Explanation } = await server.ssrLoadModule('/src/analyse/Explanation.tsx')
const render = (Component, props) => renderToStaticMarkup(createElement(Component, props))

const base = {
  score_kind: 'ranking_score',
  model_version: 'a_text-tfidf-lr-2026-10-01',
  trained_through: '2026-10-01',
  horizon_days: 90,
}
const original = 'Remote code execution in the VPN gateway. This issue has been exploited in the wild.'
const scored = {
  ...base,
  status: 'available',
  reason: 'security_cue',
  ranking_score: 0.84,
  log_odds: -3.4,
  uncalibrated_probability: 0.032,
  model_text: 'Remote code execution in the VPN gateway. This issue has been .',
  top_words: {
    up: [{ term: 'remote code', contribution: 0.3, spans: [[0, 11]] }],
    down: [{ term: 'gateway', contribution: -0.1, spans: [[33, 40]] }],
  },
  totals: { words: 0.2, char_ngrams: 3.8, intercept: -5.85, offset: -1.55 },
}
const refused = {
  ...base,
  status: 'abstained',
  reason: 'recipe_without_software_or_security_context',
  ranking_score: null,
  log_odds: null,
  uncalibrated_probability: null,
  model_text: null,
  top_words: { up: [], down: [] },
  totals: null,
}

test('score card says ranking score, not a probability, with the horizon and model', () => {
  const html = render(ScoreResult, { result: scored })
  for (const text of ['0.84', 'not a probability', 'CISA KEV within 90', 'a_text-tfidf-lr-2026-10-01', '2026-10-01']) {
    assert.ok(html.includes(text), text)
  }
})

test('refused text shows a plain reason and no score', () => {
  const html = render(ScoreResult, { result: refused })
  assert.ok(html.includes('recipe, not a vulnerability description'))
  assert.ok(html.includes('recipe_without_software_or_security_context'))
  assert.equal(render(Explanation, { result: refused, original: 'pancakes' }), '')
})

test('explanation highlights words at their offsets and shows the masked text', () => {
  const html = render(Explanation, { result: scored, original })
  assert.match(html, /<mark[^>]*>Remote code<\/mark>/)
  assert.match(html, /<mark[^>]*>gateway<\/mark>/)
  assert.ok(html.includes('leak wording removed'))
  assert.ok(html.includes('95%'), 'character-pattern share') // 3.8 / (3.8 + 0.2)
  assert.ok(html.includes('−7.40'), 'base level = intercept + offset')
})
