// SAMPLE DATA for UI development only. Not real model output.
// The CVEs are real; every score and EPSS value here is made up.

import type { Component, QueueItem, Score, ScoreStatus } from './types'

// Builds one Score with shared sample settings.
function sampleScore(
  cve_id: string,
  component: Component,
  score: number | null,
  status: ScoreStatus = 'available',
  reason: string | null = null,
): Score {
  return {
    cve_id,
    component,
    decision_time: '2026-10-16T06:00:00+00:00',
    horizon_days: 30,
    score,
    score_kind: 'ranking_score',
    status,
    reason,
    model_version: 'sample-0',
    trained_through: '2026-09-30T00:00:00+00:00',
    snapshot_date: '2026-10-16',
  }
}

// Shortcut for the common case: all four components produced a score.
function allScores(cve_id: string, text: number, timing: number, exposure: number, fused: number): Score[] {
  return [
    sampleScore(cve_id, 'a_text', text),
    sampleScore(cve_id, 'b_survival', timing),
    sampleScore(cve_id, 'c_graph', exposure),
    sampleScore(cve_id, 'd_fusion', fused),
  ]
}

// Builds one queue row with a single (vendor, product) pair.
function sampleItem(
  cve_id: string,
  description: string,
  vendor: string,
  product: string,
  cvss: number | null,
  epss: number | null,
  scores: Score[],
): QueueItem {
  return {
    vulnerability: { cve_id, description, cvss_base_score: cvss, affected: [[vendor, product]] },
    epss,
    scores,
  }
}

// Deliberately not in rank order, so the table's sorting is visible.
export const sampleQueue: QueueItem[] = [
  sampleItem('CVE-2023-0669', 'GoAnywhere MFT deserialization remote code execution', 'fortra', 'goanywhere_managed_file_transfer', 7.2, 0.81,
    allScores('CVE-2023-0669', 0.7, 0.74, 0.69, 0.76)),
  sampleItem('CVE-2024-3400', 'PAN-OS GlobalProtect command injection', 'paloaltonetworks', 'pan-os', 10.0, 0.94,
    allScores('CVE-2024-3400', 0.91, 0.88, 0.95, 0.96)),
  // No fused score: must sort to the bottom.
  sampleItem('CVE-2023-34362', 'MOVEit Transfer SQL injection', 'progress', 'moveit_transfer', 9.8, 0.94, [
    sampleScore('CVE-2023-34362', 'a_text', 0.89),
    sampleScore('CVE-2023-34362', 'b_survival', 0.85),
    sampleScore('CVE-2023-34362', 'c_graph', 0.87),
  ]),
  sampleItem('CVE-2023-4966', 'NetScaler ADC session token disclosure', 'citrix', 'netscaler_application_delivery_controller', 9.4, 0.91,
    allScores('CVE-2023-4966', 0.86, 0.9, 0.92, 0.93)),
  // Exposure abstained.
  sampleItem('CVE-2024-1709', 'ScreenConnect authentication bypass', 'connectwise', 'screenconnect', 10.0, 0.89, [
    sampleScore('CVE-2024-1709', 'a_text', 0.77),
    sampleScore('CVE-2024-1709', 'b_survival', 0.83),
    sampleScore('CVE-2024-1709', 'c_graph', null, 'abstained', 'Not enough graph evidence.'),
    sampleScore('CVE-2024-1709', 'd_fusion', 0.8),
  ]),
  // Timing: already exploited before the decision time.
  sampleItem('CVE-2021-44228', 'Log4j 2 JNDI lookup remote code execution', 'apache', 'log4j', 10.0, 0.97, [
    sampleScore('CVE-2021-44228', 'a_text', 0.94),
    sampleScore('CVE-2021-44228', 'b_survival', null, 'already_exploited', 'Exploited before decision time.'),
    sampleScore('CVE-2021-44228', 'c_graph', 0.9),
    sampleScore('CVE-2021-44228', 'd_fusion', 0.84),
  ]),
  sampleItem('CVE-2022-22965', 'Spring Framework data binding remote code execution', 'vmware', 'spring_framework', 9.8, 0.87,
    allScores('CVE-2022-22965', 0.82, 0.79, 0.9, 0.88)),
  // Made-up CVE: NVD has no CVSS yet and there is no EPSS value.
  sampleItem('CVE-2026-10001', 'Example appliance path traversal (made-up record)', 'example', 'edge_gateway', null, null,
    allScores('CVE-2026-10001', 0.58, 0.6, 0.55, 0.61)),
]
