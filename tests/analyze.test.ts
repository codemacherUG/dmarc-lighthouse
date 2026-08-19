import { describe, expect, it } from 'vitest'
import {
  analyzeFromReports,
  applyDashboardFilter,
  buildDashboard,
  filterForensicReports,
  filterReports,
  groupProblemSources,
  isGoogleIpInfo,
  isHarmonyIpInfo,
  isMailboxIpInfo,
  isMailboxNoiseRecord,
  matchesDispositionFilter,
  recordMatchesSourceIp
} from '../src/shared/analyze'
import type { ForensicReportRow, ReportRow, SerializedRecord } from '../src/shared/types'

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

  it('filters a single custom day by the UTC date key used in the volume chart', () => {
    const rows = [
      report({ reportId: 'prev', dateEnd: '2026-07-12T23:00:00.000Z' }),
      report({ reportId: 'hit', dateEnd: '2026-07-13T22:30:00.000Z' }),
      report({ reportId: 'next', dateEnd: '2026-07-14T01:00:00.000Z' })
    ]
    const out = filterReports(rows, {
      range: 'custom',
      from: '2026-07-13',
      to: '2026-07-13',
      domain: ''
    })
    expect(out.map((r) => r.reportId)).toEqual(['hit'])
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

  it('filters records by a comma-separated source IP group', () => {
    const rows = [
      report({
        records: [
          record({ sourceIp: '40.93.64.65', count: 2, passesDmarc: false }),
          record({ sourceIp: '40.93.64.95', count: 1, passesDmarc: false }),
          record({ sourceIp: '192.0.2.1', count: 4, passesDmarc: true })
        ]
      })
    ]
    const out = filterReports(rows, {
      range: 'all',
      domain: '',
      sourceIp: '40.93.64.65,40.93.64.95'
    })
    expect(out).toHaveLength(1)
    expect(out[0].records.map((r) => r.sourceIp)).toEqual(['40.93.64.65', '40.93.64.95'])
    expect(out[0].total).toBe(3)
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

  it('hides mailbox SPF-fail / DKIM-pass noise and keeps real sources', () => {
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
      hideMailboxNoise: true,
      mailboxIps: new Set([googleIp])
    })
    expect(out).toHaveLength(1)
    expect(out[0].records.map((r) => ({ ip: r.sourceIp, count: r.count }))).toEqual([
      { ip: ownIp, count: 3 },
      { ip: googleIp, count: 1 }
    ])
    expect(out[0].total).toBe(4)
    expect(out[0].passing).toBe(3)
  })

  it('hides mailbox noise via well-known prefixes without enrichment', () => {
    const googleIp = '2a00:1450:4864:20::346'
    const outlookIp = '40.92.0.10'
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
            sourceIp: outlookIp,
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
    const out = filterReports(rows, { range: 'all', domain: '', hideMailboxNoise: true })
    expect(out).toHaveLength(1)
    expect(out[0].total).toBe(3)
    expect(out[0].records).toHaveLength(1)
    expect(out[0].records[0]?.sourceIp).toBe('159.195.74.209')
  })

  it('keeps only records with applied disposition reject', () => {
    const rows = [
      report({
        reportId: 'mixed',
        records: [
          record({ disposition: 'none', count: 4 }),
          record({ disposition: 'quarantine', count: 2, passesDmarc: false }),
          record({ disposition: 'reject', count: 3, passesDmarc: false })
        ]
      }),
      report({
        reportId: 'none-only',
        records: [record({ disposition: 'none', count: 1 })]
      })
    ]
    const out = filterReports(rows, { range: 'all', domain: '', disposition: 'reject' })
    expect(out).toHaveLength(1)
    expect(out[0].reportId).toBe('mixed')
    expect(out[0].records).toHaveLength(1)
    expect(out[0].records[0]?.disposition).toBe('reject')
    expect(out[0].total).toBe(3)
    expect(out[0].failing).toBe(3)
  })

  it('keeps none and quarantine when filtering to not-reject', () => {
    const rows = [
      report({
        records: [
          record({ disposition: 'none', count: 4 }),
          record({ disposition: 'quarantine', count: 2, passesDmarc: false }),
          record({ disposition: 'reject', count: 3, passesDmarc: false })
        ]
      })
    ]
    const out = filterReports(rows, { range: 'all', domain: '', disposition: 'not-reject' })
    expect(out).toHaveLength(1)
    expect(out[0].records.map((r) => r.disposition)).toEqual(['none', 'quarantine'])
    expect(out[0].total).toBe(6)
  })
})

describe('matchesDispositionFilter', () => {
  it('treats reject and rejected as reject, everything else as not-reject', () => {
    expect(matchesDispositionFilter('reject', 'reject')).toBe(true)
    expect(matchesDispositionFilter('Rejected', 'reject')).toBe(true)
    expect(matchesDispositionFilter('quarantine', 'reject')).toBe(false)
    expect(matchesDispositionFilter('none', 'not-reject')).toBe(true)
    expect(matchesDispositionFilter('', 'not-reject')).toBe(true)
    expect(matchesDispositionFilter('reject', 'not-reject')).toBe(false)
    expect(matchesDispositionFilter('reject', 'all')).toBe(true)
  })
})

describe('filterForensicReports', () => {
  function forensic(overrides: Partial<ForensicReportRow> = {}): ForensicReportRow {
    return {
      id: 'f-1',
      reportId: 'ruf-1',
      orgName: 'google.com',
      reportedDomain: 'example.com',
      arrivalDate: '2026-07-02T00:00:00.000Z',
      sourceIp: '192.0.2.1',
      authFailure: 'dmarc',
      deliveryResult: 'delivered',
      envelopeFrom: null,
      headerFrom: 'example.com',
      originalRcptTo: null,
      authenticationResults: null,
      subject: null,
      feedbackType: null,
      ...overrides
    }
  }

  it('filters forensic rows by delivery-result reject vs not-reject', () => {
    const rows = [
      forensic({ id: 'a', deliveryResult: 'reject' }),
      forensic({ id: 'b', deliveryResult: 'rejected' }),
      forensic({ id: 'c', deliveryResult: 'delivered' }),
      forensic({ id: 'd', deliveryResult: null })
    ]
    expect(
      filterForensicReports(rows, { range: 'all', domain: '', disposition: 'reject' }).map(
        (r) => r.id
      )
    ).toEqual(['a', 'b'])
    expect(
      filterForensicReports(rows, { range: 'all', domain: '', disposition: 'not-reject' }).map(
        (r) => r.id
      )
    ).toEqual(['c', 'd'])
  })
})

describe('isGoogleIpInfo / isMailboxIpInfo / isMailboxNoiseRecord', () => {
  it('detects Google via cloud, provider, ASN, and asOrg', () => {
    expect(
      isGoogleIpInfo({ cloudProvider: 'Google', provider: null, asn: null, asOrg: null })
    ).toBe(true)
    expect(
      isGoogleIpInfo({ cloudProvider: null, provider: 'Google', asn: null, asOrg: null })
    ).toBe(true)
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

  it('detects mailbox providers via sender kind, product name, and ASN', () => {
    expect(
      isMailboxIpInfo({
        cloudProvider: null,
        provider: 'Microsoft 365',
        asn: null,
        asOrg: null,
        senderKind: 'mailbox'
      })
    ).toBe(true)
    expect(
      isMailboxIpInfo({
        cloudProvider: null,
        provider: 'Yahoo',
        asn: null,
        asOrg: null,
        senderKind: null
      })
    ).toBe(true)
    expect(
      isMailboxIpInfo({
        cloudProvider: 'Microsoft',
        provider: 'Azure',
        asn: 8075,
        asOrg: 'Microsoft Corporation',
        senderKind: 'infra'
      })
    ).toBe(false)
  })

  it('matches only SPF-fail + DKIM-pass + DMARC-pass on mailbox IPs', () => {
    expect(
      isMailboxNoiseRecord(
        record({
          sourceIp: '2a00:1450:4864:20::346',
          spfResult: 'fail',
          dkimResult: 'pass',
          passesDmarc: true
        })
      )
    ).toBe(true)
    expect(
      isMailboxNoiseRecord(
        record({
          sourceIp: '40.92.0.10',
          spfResult: 'fail',
          dkimResult: 'pass',
          passesDmarc: true
        })
      )
    ).toBe(true)
    expect(
      isMailboxNoiseRecord(
        record({
          sourceIp: '2a00:1450:4864:20::346',
          spfResult: 'fail',
          dkimResult: 'pass',
          passesDmarc: false
        })
      )
    ).toBe(false)
    expect(
      isMailboxNoiseRecord(
        record({
          sourceIp: '192.0.2.1',
          spfResult: 'fail',
          dkimResult: 'pass',
          passesDmarc: true
        })
      )
    ).toBe(false)
    // Enrichment can mark non-prefix IPs as mailbox too.
    expect(
      isMailboxNoiseRecord(
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

  it('treats Check Point Harmony re-injection as noise once the IP is known', () => {
    const harmony = record({
      sourceIp: '3.5.140.1',
      spfResult: 'fail',
      dkimResult: 'fail',
      passesDmarc: false,
      disposition: 'none'
    })
    expect(isMailboxNoiseRecord(harmony)).toBe(false)
    expect(isMailboxNoiseRecord(harmony, undefined, new Set(['3.5.140.1']))).toBe(true)
    expect(
      isMailboxNoiseRecord(
        record({
          sourceIp: '3.5.140.1',
          spfResult: 'fail',
          dkimResult: 'fail',
          passesDmarc: true
        }),
        undefined,
        new Set(['3.5.140.1'])
      )
    ).toBe(false)
    expect(
      isMailboxNoiseRecord(
        record({
          sourceIp: '3.5.140.1',
          spfResult: 'fail',
          dkimResult: 'fail',
          passesDmarc: false,
          disposition: 'reject'
        }),
        undefined,
        new Set(['3.5.140.1'])
      )
    ).toBe(false)
    expect(
      isHarmonyIpInfo({ provider: 'Check Point Harmony', ptr: 'ec2.amazonaws.com' })
    ).toBe(true)
    expect(
      isHarmonyIpInfo({ provider: 'AWS', ptr: 'mail.eu.cloud-sec-av.com' })
    ).toBe(true)
    expect(isHarmonyIpInfo({ provider: 'AWS', ptr: 'ec2.amazonaws.com' })).toBe(false)
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
        headerFrom: 'example.com',
        categories: { broken: 4 },
        category: 'broken'
      }
    ])
  })
})

describe('groupProblemSources', () => {
  const ms = { asn: 8075, provider: 'Microsoft', cloudProvider: 'Microsoft' as string | null }

  it('merges IPs that share ASN and From', () => {
    const grouped = groupProblemSources(
      [
        {
          sourceIp: '40.93.64.65',
          count: 2,
          spfFail: 2,
          dkimFail: 2,
          headerFrom: 'mgne-hamburg.de'
        },
        {
          sourceIp: '40.93.64.95',
          count: 1,
          spfFail: 1,
          dkimFail: 1,
          headerFrom: 'mgne-hamburg.de'
        },
        {
          sourceIp: '40.93.214.96',
          count: 1,
          spfFail: 1,
          dkimFail: 1,
          headerFrom: 'mgne-hamburg.de'
        }
      ],
      () => ms
    )
    expect(grouped).toHaveLength(1)
    expect(grouped[0]).toMatchObject({
      sourceIp: '40.93.64.65',
      count: 4,
      spfFail: 4,
      dkimFail: 4,
      headerFrom: 'mgne-hamburg.de'
    })
    expect(grouped[0]?.extraIps?.sort()).toEqual(['40.93.214.96', '40.93.64.95'])
  })

  it('keeps the same ASN separate when From differs', () => {
    const grouped = groupProblemSources(
      [
        {
          sourceIp: '40.93.64.65',
          count: 2,
          spfFail: 2,
          dkimFail: 2,
          headerFrom: 'a.example'
        },
        {
          sourceIp: '40.93.64.95',
          count: 1,
          spfFail: 1,
          dkimFail: 1,
          headerFrom: 'b.example'
        }
      ],
      () => ms
    )
    expect(grouped).toHaveLength(2)
  })

  it('leaves unenriched IPs ungrouped', () => {
    const grouped = groupProblemSources(
      [
        {
          sourceIp: '40.93.64.65',
          count: 2,
          spfFail: 2,
          dkimFail: 2,
          headerFrom: 'mgne-hamburg.de'
        },
        {
          sourceIp: '40.93.64.95',
          count: 1,
          spfFail: 1,
          dkimFail: 1,
          headerFrom: 'mgne-hamburg.de'
        }
      ],
      () => null
    )
    expect(grouped).toHaveLength(2)
    expect(grouped.every((r) => !r.extraIps?.length)).toBe(true)
  })

  it('sums failure categories of merged IPs and keeps the dominant one', () => {
    const grouped = groupProblemSources(
      [
        {
          sourceIp: '40.93.64.65',
          count: 3,
          spfFail: 3,
          dkimFail: 3,
          headerFrom: 'example.com',
          categories: { forwarder: 1, thirdParty: 2 },
          category: 'thirdParty'
        },
        {
          sourceIp: '40.93.64.95',
          count: 5,
          spfFail: 5,
          dkimFail: 5,
          headerFrom: 'example.com',
          categories: { forwarder: 5 },
          category: 'forwarder'
        }
      ],
      () => ms
    )
    expect(grouped).toHaveLength(1)
    expect(grouped[0]?.categories).toEqual({ forwarder: 6, thirdParty: 2 })
    expect(grouped[0]?.category).toBe('forwarder')
  })

  it('matches a single IP or a group in the source-IP filter', () => {
    expect(recordMatchesSourceIp('40.93.64.65', '40.93.64.65')).toBe(true)
    expect(recordMatchesSourceIp('40.93.64.95', '40.93.64.65,40.93.64.95')).toBe(true)
    expect(recordMatchesSourceIp('192.0.2.1', '40.93.64.65,40.93.64.95')).toBe(false)
    expect(recordMatchesSourceIp('192.0.2.1', undefined)).toBe(true)
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

describe('applyDashboardFilter', () => {
  it('reuses the full result when nothing is dropped or mutated', () => {
    const full = analyzeFromReports([report()])
    const out = applyDashboardFilter(full, { range: 'all', domain: '' })
    expect(out).toBe(full)
  })

  it('rebuilds when the date window drops reports', () => {
    const recentEnd = new Date()
    recentEnd.setHours(12, 0, 0, 0)
    const old = report({
      reportId: 'old',
      dateBegin: '2020-01-01T00:00:00.000Z',
      dateEnd: '2020-01-02T00:00:00.000Z'
    })
    const recent = report({
      reportId: 'new',
      dateBegin: recentEnd.toISOString(),
      dateEnd: recentEnd.toISOString()
    })
    const full = analyzeFromReports([recent, old])
    const out = applyDashboardFilter(full, { range: '90', domain: '' })
    expect(out).not.toBe(full)
    expect(out.reports.map((r) => r.reportId)).toEqual(['new'])
  })

  it('rebuilds totals when filtering by applied disposition', () => {
    const full = analyzeFromReports([
      report({
        records: [
          record({ disposition: 'none', count: 5 }),
          record({ disposition: 'reject', count: 2, passesDmarc: false })
        ]
      })
    ])
    const out = applyDashboardFilter(full, { range: 'all', domain: '', disposition: 'reject' })
    expect(out).not.toBe(full)
    expect(out.aggregate.total).toBe(2)
    expect(out.dashboard.dispositions.map((b) => b.name)).toEqual(['reject'])
  })

  it('drops Check Point Harmony IPs from problem sources without hiding other fails', () => {
    const harmonyIp = '3.5.140.1'
    const otherIp = '203.0.113.9'
    const full = analyzeFromReports([
      report({
        records: [
          record({
            sourceIp: harmonyIp,
            count: 4,
            passesDmarc: false,
            disposition: 'none',
            spfResult: 'fail',
            dkimResult: 'fail'
          }),
          record({
            sourceIp: otherIp,
            count: 2,
            passesDmarc: false,
            disposition: 'none',
            spfResult: 'fail',
            dkimResult: 'fail'
          })
        ]
      })
    ])
    expect(full.dashboard.problemSources.map((s) => s.sourceIp)).toEqual([harmonyIp, otherIp])
    const out = applyDashboardFilter(full, {
      range: 'all',
      domain: '',
      harmonyIps: new Set([harmonyIp])
    })
    expect(out.dashboard.problemSources.map((s) => s.sourceIp)).toEqual([otherIp])
    expect(out.aggregate.failing).toBe(6)
  })

  it('hides Harmony re-injection from KPIs when mailbox noise is on', () => {
    const harmonyIp = '3.5.140.1'
    const ownIp = '159.195.74.209'
    const full = analyzeFromReports([
      report({
        records: [
          record({
            sourceIp: ownIp,
            count: 3,
            spfResult: 'pass',
            dkimResult: 'pass',
            passesDmarc: true
          }),
          record({
            sourceIp: harmonyIp,
            count: 2,
            spfResult: 'fail',
            dkimResult: 'fail',
            passesDmarc: false,
            disposition: 'none'
          })
        ]
      })
    ])
    const out = applyDashboardFilter(full, {
      range: 'all',
      domain: '',
      hideMailboxNoise: true,
      harmonyIps: new Set([harmonyIp])
    })
    expect(out.aggregate.total).toBe(3)
    expect(out.aggregate.failing).toBe(0)
    expect(out.dashboard.problemSources).toEqual([])
  })
})
