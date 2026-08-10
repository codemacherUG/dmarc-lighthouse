import { describe, expect, it } from 'vitest'
import {
  analyzeFromReports,
  buildDashboard,
  filterReports,
  isGoogleIpInfo,
  isGoogleNoiseRecord
} from '../src/shared/analyze'
import type { ReportRow, SerializedRecord } from '../src/shared/types'

function record(overrides: Partial<SerializedRecord> = {}): SerializedRecord {
  return {
    sourceIp: '192.0.2.1',
    count: 1,
    disposition: 'none',
    dkimResult: 'pass',
    spfResult: 'pass',
    headerFrom: 'example.com',
    dkimDomain: 'example.com',
    spfDomain: 'example.com',
    dkimSelectors: [],
    passesDmarc: true,
    reasons: [],
    ...overrides
  }
}

function report(overrides: Partial<ReportRow> = {}): ReportRow {
  const records = overrides.records ?? [record()]
  let total = 0
  let passing = 0
  for (const rec of records) {
    total += rec.count
    if (rec.passesDmarc) passing += rec.count
  }
  return {
    reportId: 'r-1',
    orgName: 'google.com',
    domain: 'example.com',
    dateBegin: '2026-07-01T00:00:00.000Z',
    dateEnd: '2026-07-02T00:00:00.000Z',
    total,
    passing,
    failing: total - passing,
    passRate: total ? Math.round((passing / total) * 1000) / 10 : 0,
    policyP: 'none',
    ...overrides,
    records
  }
}

describe('filterReports', () => {
  it('filters by domain (case-insensitive)', () => {
    const rows = [report({ reportId: 'a' }), report({ reportId: 'b', domain: 'other.org' })]
    const out = filterReports(rows, { range: 'all', domain: 'EXAMPLE.com' })
    expect(out.map((r) => r.reportId)).toEqual(['a'])
  })

  it('filters by custom date range inclusively', () => {
    const rows = [
      report({ reportId: 'old', dateEnd: '2026-06-01T12:00:00.000Z' }),
      report({ reportId: 'in', dateEnd: '2026-07-02T12:00:00.000Z' }),
      report({ reportId: 'new', dateEnd: '2026-08-01T12:00:00.000Z' })
    ]
    const out = filterReports(rows, {
      range: 'custom',
      from: '2026-07-01',
      to: '2026-07-31',
      domain: ''
    })
    expect(out.map((r) => r.reportId)).toEqual(['in'])
  })

  it('ignores custom bounds when range is a preset', () => {
    const rows = [report({ reportId: 'a', dateEnd: '2026-06-01T00:00:00.000Z' })]
    const out = filterReports(rows, { range: 'all', from: '2026-07-01', domain: '' })
    expect(out).toHaveLength(1)
  })

  it('filters by reporting organization', () => {
    const rows = [
      report({ reportId: 'a', orgName: 'google.com' }),
      report({ reportId: 'b', orgName: 'yahoo.com' })
    ]
    const out = filterReports(rows, { range: 'all', domain: '', org: 'yahoo.com' })
    expect(out.map((r) => r.reportId)).toEqual(['b'])
  })

  it('filters records by source IP and recomputes totals', () => {
    const rows = [
      report({
        reportId: 'a',
        records: [
          record({ sourceIp: '192.0.2.1', count: 5, passesDmarc: true }),
          record({ sourceIp: '198.51.100.9', count: 3, passesDmarc: false })
        ]
      })
    ]
    const out = filterReports(rows, { range: 'all', domain: '', sourceIp: '198.51.100.9' })
    expect(out).toHaveLength(1)
    expect(out[0].records).toHaveLength(1)
    expect(out[0].total).toBe(3)
    expect(out[0].passing).toBe(0)
    expect(out[0].failing).toBe(3)
    expect(out[0].passRate).toBe(0)
  })

  it('drops reports without matching records', () => {
    const rows = [report({ records: [record({ sourceIp: '192.0.2.1' })] })]
    const out = filterReports(rows, { range: 'all', domain: '', sourceIp: '203.0.113.7' })
    expect(out).toHaveLength(0)
  })

  it('filters by header-from including the unknown fallback', () => {
    const rows = [
      report({
        records: [
          record({ headerFrom: null, count: 2 }),
          record({ headerFrom: 'example.com', count: 4 })
        ]
      })
    ]
    const out = filterReports(rows, { range: 'all', domain: '', headerFrom: '(unbekannt)' })
    expect(out).toHaveLength(1)
    expect(out[0].total).toBe(2)
  })

  it('hides Google SPF-fail / DKIM-pass noise and keeps real sources', () => {
    const googleIp = '2a00:1450:4864:20::346'
    const ownIp = '159.195.74.209'
    const rows = [
      report({
        reportId: 'a',
        records: [
          record({
            sourceIp: ownIp,
            count: 3,
            spfResult: 'pass',
            dkimResult: 'pass',
            passesDmarc: true
          }),
          record({
            sourceIp: googleIp,
            count: 2,
            spfResult: 'fail',
            dkimResult: 'pass',
            passesDmarc: true
          }),
          record({
            sourceIp: googleIp,
            count: 1,
            spfResult: 'fail',
            dkimResult: 'fail',
            passesDmarc: false
          })
        ]
      })
    ]
    const out = filterReports(rows, {
      range: 'all',
      domain: '',
      hideGoogleNoise: true,
      googleIps: new Set([googleIp])
    })
    expect(out).toHaveLength(1)
    expect(out[0].records.map((r) => ({ ip: r.sourceIp, count: r.count }))).toEqual([
      { ip: ownIp, count: 3 },
      { ip: googleIp, count: 1 }
    ])
    expect(out[0].total).toBe(4)
    expect(out[0].passing).toBe(3)
  })

  it('hides Google noise via well-known prefixes without enrichment', () => {
    const googleIp = '2a00:1450:4864:20::346'
    const rows = [
      report({
        records: [
          record({
            sourceIp: googleIp,
            count: 2,
            spfResult: 'fail',
            dkimResult: 'pass',
            passesDmarc: true
          }),
          record({
            sourceIp: '159.195.74.209',
            count: 3,
            spfResult: 'pass',
            dkimResult: 'pass',
            passesDmarc: true
          })
        ]
      })
    ]
    const out = filterReports(rows, { range: 'all', domain: '', hideGoogleNoise: true })
    expect(out).toHaveLength(1)
    expect(out[0].total).toBe(3)
    expect(out[0].records).toHaveLength(1)
    expect(out[0].records[0]?.sourceIp).toBe('159.195.74.209')
  })
})

describe('isGoogleIpInfo / isGoogleNoiseRecord', () => {
  it('detects Google via cloud, provider, ASN, and asOrg', () => {
    expect(isGoogleIpInfo({ cloudProvider: 'Google', provider: null, asn: null, asOrg: null })).toBe(
      true
    )
    expect(isGoogleIpInfo({ cloudProvider: null, provider: 'Google', asn: null, asOrg: null })).toBe(
      true
    )
    expect(isGoogleIpInfo({ cloudProvider: null, provider: null, asn: 15169, asOrg: null })).toBe(
      true
    )
    expect(
      isGoogleIpInfo({ cloudProvider: null, provider: null, asn: null, asOrg: 'GOOGLE' })
    ).toBe(true)
    expect(
      isGoogleIpInfo({ cloudProvider: null, provider: 'Microsoft', asn: null, asOrg: null })
    ).toBe(false)
  })

  it('matches only SPF-fail + DKIM-pass + DMARC-pass on Google IPs', () => {
    expect(
      isGoogleNoiseRecord(
        record({
          sourceIp: '2a00:1450:4864:20::346',
          spfResult: 'fail',
          dkimResult: 'pass',
          passesDmarc: true
        })
      )
    ).toBe(true)
    expect(
      isGoogleNoiseRecord(
        record({
          sourceIp: '2a00:1450:4864:20::346',
          spfResult: 'fail',
          dkimResult: 'pass',
          passesDmarc: false
        })
      )
    ).toBe(false)
    expect(
      isGoogleNoiseRecord(
        record({
          sourceIp: '192.0.2.1',
          spfResult: 'fail',
          dkimResult: 'pass',
          passesDmarc: true
        })
      )
    ).toBe(false)
    // Enrichment can mark non-prefix IPs as Google too.
    expect(
      isGoogleNoiseRecord(
        record({
          sourceIp: '203.0.113.50',
          spfResult: 'fail',
          dkimResult: 'pass',
          passesDmarc: true
        }),
        new Set(['203.0.113.50'])
      )
    ).toBe(true)
  })
})

describe('buildDashboard', () => {
  it('aggregates dispositions across records', () => {
    const rows = [
      report({
        records: [
          record({ disposition: 'none', count: 6 }),
          record({ disposition: 'reject', count: 3, passesDmarc: false }),
          record({ disposition: null, count: 1 })
        ]
      })
    ]
    const d = buildDashboard(rows)
    const byName = Object.fromEntries(d.dispositions.map((b) => [b.name, b.count]))
    expect(byName).toEqual({ none: 7, reject: 3 })
  })

  it('computes alignment breakdowns', () => {
    const rows = [
      report({
        records: [
          record({ count: 2, dkimResult: 'pass', spfResult: 'fail', passesDmarc: true }),
          record({ count: 1, dkimResult: null, spfResult: 'pass', passesDmarc: false })
        ]
      })
    ]
    const d = buildDashboard(rows)
    expect(d.dmarc).toEqual({ pass: 2, fail: 1, other: 0 })
    expect(d.dkim).toEqual({ pass: 2, fail: 0, other: 1 })
    expect(d.spf).toEqual({ pass: 1, fail: 2, other: 0 })
  })

  it('includes problemSources for delivered auth-fails', () => {
    const d = buildDashboard([
      report({
        records: [
          record({
            sourceIp: '203.0.113.9',
            count: 4,
            passesDmarc: false,
            disposition: 'none',
            spfResult: 'fail',
            dkimResult: 'fail'
          }),
          record({
            sourceIp: '203.0.113.9',
            count: 1,
            passesDmarc: false,
            disposition: 'reject',
            spfResult: 'fail',
            dkimResult: 'fail'
          })
        ]
      })
    ])
    expect(d.problemSources).toEqual([
      {
        sourceIp: '203.0.113.9',
        count: 4,
        spfFail: 4,
        dkimFail: 4,
        headerFrom: 'example.com'
      }
    ])
  })
})

describe('analyzeFromReports', () => {
  it('aggregates totals, date range and domains', () => {
    const rows = [
      report({
        reportId: 'a',
        domain: 'a.example',
        dateBegin: '2026-07-01T00:00:00.000Z',
        dateEnd: '2026-07-02T00:00:00.000Z',
        records: [record({ count: 4 })]
      }),
      report({
        reportId: 'b',
        domain: 'b.example',
        dateBegin: '2026-07-03T00:00:00.000Z',
        dateEnd: '2026-07-04T00:00:00.000Z',
        records: [record({ count: 6, passesDmarc: false })]
      })
    ]
    const result = analyzeFromReports(rows)
    expect(result.aggregate.reportCount).toBe(2)
    expect(result.aggregate.total).toBe(10)
    expect(result.aggregate.passing).toBe(4)
    expect(result.aggregate.failing).toBe(6)
    expect(result.aggregate.passRate).toBe(40)
    expect(result.aggregate.dateBegin).toBe('2026-07-01T00:00:00.000Z')
    expect(result.aggregate.dateEnd).toBe('2026-07-04T00:00:00.000Z')
    expect(result.aggregate.domains).toEqual(['a.example', 'b.example'])
  })

  it('returns an empty result for no reports', () => {
    const result = analyzeFromReports([])
    expect(result.aggregate.reportCount).toBe(0)
    expect(result.reports).toEqual([])
  })
})
