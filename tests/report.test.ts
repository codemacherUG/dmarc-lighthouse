import { describe, expect, it } from 'vitest'
import { looksLikePdf, chromeCandidates, groupReportsByDomain } from '../src/main/pdf-report'
import { analyzeFromReports } from '../src/shared/analyze'
import { buildFindings, buildManagementReportHtml } from '../src/shared/report-html'
import {
  isMonthlyReportDue,
  monthLabel,
  monthlyReportFilename,
  periodForReports,
  previousMonthRange
} from '../src/shared/report-period'
import type { AnalyzeResult, ReportRow, SerializedRecord } from '../src/shared/types'

function record(over: Partial<SerializedRecord> = {}): SerializedRecord {
  return {
    sourceIp: '198.51.100.10',
    count: 10,
    disposition: 'none',
    dkimResult: 'pass',
    spfResult: 'pass',
    headerFrom: 'example.com',
    dkimDomain: 'example.com',
    spfDomain: 'example.com',
    dkimSelectors: ['sel1'],
    passesDmarc: true,
    reasons: [],
    ...over
  }
}

function report(over: Partial<ReportRow> = {}): ReportRow {
  const records = over.records ?? [record()]
  const total = records.reduce((sum, r) => sum + r.count, 0)
  const passing = records.filter((r) => r.passesDmarc).reduce((sum, r) => sum + r.count, 0)
  return {
    reportId: 'r1',
    orgName: 'google.com',
    domain: 'example.com',
    dateBegin: '2026-07-05T00:00:00.000Z',
    dateEnd: '2026-07-06T00:00:00.000Z',
    total,
    passing,
    failing: total - passing,
    passRate: total ? Math.round((passing / total) * 1000) / 10 : 0,
    policyP: 'none',
    ...over,
    records
  }
}

describe('previousMonthRange', () => {
  it('covers the whole month before now', () => {
    const period = previousMonthRange(new Date(2026, 7, 13, 19, 30))
    expect(period.month).toBe('2026-07')
    expect(new Date(period.from).getMonth()).toBe(6)
    expect(new Date(period.from).getDate()).toBe(1)
    expect(new Date(period.to).getMonth()).toBe(7)
    expect(new Date(period.to).getDate()).toBe(1)
  })

  it('wraps into the previous year in January', () => {
    const period = previousMonthRange(new Date(2027, 0, 4))
    expect(period.month).toBe('2026-12')
  })
})

describe('periodForReports', () => {
  const now = new Date(2026, 7, 13)

  it('prefers the finished month when data overlaps it', () => {
    const period = periodForReports(['2026-07-20T00:00:00.000Z', '2026-08-11T00:00:00.000Z'], now)
    expect(period?.month).toBe('2026-07')
  })

  it('falls back to the latest month when the finished month is empty', () => {
    const period = periodForReports(['2026-08-11T00:00:00.000Z', '2026-08-12T23:59:59.000Z'], now)
    expect(period?.month).toBe('2026-08')
  })

  it('returns null without timestamps', () => {
    expect(periodForReports([], now)).toBeNull()
  })
})

describe('isMonthlyReportDue', () => {
  const now = new Date(2026, 7, 13)

  it('is due without a previous run', () => {
    expect(isMonthlyReportDue(null, now)).toBe(true)
    expect(isMonthlyReportDue('not-a-date', now)).toBe(true)
  })

  it('is due when the last run predates the finished month', () => {
    expect(isMonthlyReportDue(new Date(2026, 6, 2).toISOString(), now)).toBe(true)
  })

  it('is not due again in the same month', () => {
    expect(isMonthlyReportDue(new Date(2026, 7, 1, 6).toISOString(), now)).toBe(false)
    expect(isMonthlyReportDue(new Date(2026, 7, 12).toISOString(), now)).toBe(false)
  })
})

describe('monthLabel and filename', () => {
  it('localizes the month', () => {
    expect(monthLabel('2026-07', 'de')).toBe('Juli 2026')
    expect(monthLabel('2026-07', 'en')).toBe('July 2026')
  })

  it('builds a filesystem-safe name', () => {
    expect(monthlyReportFilename('Example.COM', '2026-07')).toBe(
      'dmarc-report-example.com-2026-07.pdf'
    )
    expect(monthlyReportFilename(null, '2026-07')).toBe('dmarc-report-all-domains-2026-07.pdf')
    expect(monthlyReportFilename('all mail/domains', '2026-07')).toBe(
      'dmarc-report-all-mail-domains-2026-07.pdf'
    )
  })
})

describe('groupReportsByDomain', () => {
  it('splits one mailbox into one slice per domain', () => {
    const slices = groupReportsByDomain([
      {
        label: 'inbox',
        reports: [
          report({ reportId: 'a', domain: 'example.com' }),
          report({ reportId: 'b', domain: 'other.test' })
        ],
        forensicReports: []
      }
    ])
    expect(slices.map((s) => s.domain)).toEqual(['example.com', 'other.test'])
    expect(slices[0].reports).toHaveLength(1)
    expect(slices[1].reports).toHaveLength(1)
    expect(slices.every((s) => s.accountLabels[0] === 'inbox')).toBe(true)
  })

  it('merges the same domain from two accounts and dedupes reports', () => {
    const row = report({ reportId: 'same', orgName: 'google.com', domain: 'example.com' })
    const slices = groupReportsByDomain([
      { label: 'a', reports: [row], forensicReports: [] },
      {
        label: 'b',
        reports: [row, report({ reportId: 'extra', orgName: 'yahoo.com', domain: 'example.com' })],
        forensicReports: []
      }
    ])
    expect(slices).toHaveLength(1)
    expect(slices[0].domain).toBe('example.com')
    expect(slices[0].reports).toHaveLength(2)
    expect(slices[0].accountLabels).toEqual(['a', 'b'])
  })

  it('attaches forensic rows to the reported domain even without aggregates', () => {
    const slices = groupReportsByDomain([
      {
        label: 'inbox',
        reports: [],
        forensicReports: [
          {
            id: 'f1',
            reportId: null,
            orgName: null,
            reportedDomain: 'Example.COM',
            arrivalDate: '2026-07-02T00:00:00.000Z',
            sourceIp: '203.0.113.9',
            authFailure: 'dmarc',
            deliveryResult: null,
            envelopeFrom: null,
            headerFrom: 'billing@example.com',
            originalRcptTo: null,
            authenticationResults: null,
            subject: null,
            feedbackType: 'auth-failure'
          }
        ]
      }
    ])
    expect(slices).toHaveLength(1)
    expect(slices[0].domain).toBe('example.com')
    expect(slices[0].reports).toHaveLength(0)
    expect(slices[0].forensicReports).toHaveLength(1)
  })
})

describe('buildFindings', () => {
  it('reports missing data instead of guessing', () => {
    const result = analyzeFromReports([])
    expect(buildFindings({ result })).toEqual([{ key: 'pdf.finding.noData', level: 'warn' }])
  })

  it('flags a healthy domain as ready for the next step', () => {
    const result = analyzeFromReports([report()])
    const keys = buildFindings({ result }).map((f) => f.key)
    expect(keys).toContain('pdf.finding.passRateGood')
  })

  it('escalates unauthenticated delivered mail', () => {
    const spoofed = report({
      reportId: 'r2',
      records: [
        record({ count: 40 }),
        record({
          sourceIp: '203.0.113.9',
          count: 12,
          dkimResult: 'none',
          spfResult: 'none',
          dkimDomain: null,
          spfDomain: null,
          passesDmarc: false
        })
      ]
    })
    const result = analyzeFromReports([spoofed])
    const findings = buildFindings({ result })
    const spoof = findings.find((f) => f.key === 'pdf.finding.spoof')
    expect(spoof?.level).toBe('bad')
    expect(spoof?.params?.count).toBe(12)
  })

  it('picks up the DNS policy state when domain health is known', () => {
    const result = analyzeFromReports([report()])
    const findings = buildFindings({
      result,
      domains: [
        {
          domain: 'example.com',
          total: 10,
          passing: 10,
          failing: 0,
          passRate: 100,
          dkimSelectors: [],
          dmarcPolicy: 'none',
          spfOk: true,
          dkimOk: true,
          status: 'warn',
          reasons: []
        }
      ]
    })
    const none = findings.find((f) => f.key === 'pdf.finding.policyNone')
    expect(none?.params?.domains).toBe('example.com')
  })
})

describe('buildManagementReportHtml', () => {
  const result: AnalyzeResult = analyzeFromReports([report()])

  it('renders a self-contained document with the key figures', () => {
    const html = buildManagementReportHtml({
      result,
      locale: 'de',
      month: '2026-07',
      domain: 'example.com',
      appVersion: '1.2.3'
    })
    expect(html.startsWith('<!DOCTYPE html>')).toBe(true)
    expect(html).not.toMatch(/<(script|link|img)\b/)
    expect(html).toContain('Juli 2026')
    expect(html).toContain('example.com')
    expect(html).toContain('1.2.3')
    expect(html).toContain('DMARC Lighthouse')
    expect(html).toContain('codemacher')
    expect(html).toContain('https://codemacher.de')
    // Brand mark, three alignment donuts, and the daily volume chart.
    expect(html.match(/<svg/g)?.length).toBe(5)
  })

  it('works without data and without a month', () => {
    const html = buildManagementReportHtml({ result: analyzeFromReports([]), locale: 'en' })
    expect(html).toContain('All domains')
    expect(html).toContain('No reports available for this period.')
  })

  it('escapes report content', () => {
    const evil = analyzeFromReports([
      report({ orgName: '<script>alert(1)</script>', reportId: 'r3' })
    ])
    const html = buildManagementReportHtml({ result: evil, locale: 'de' })
    expect(html).not.toContain('<script>alert(1)</script>')
    expect(html).toContain('&lt;script&gt;')
  })
})

describe('looksLikePdf', () => {
  it('recognizes a PDF header', () => {
    expect(looksLikePdf(Buffer.from('%PDF-1.4\n'))).toBe(true)
    expect(looksLikePdf(Buffer.from('<!DOCTYPE html>'))).toBe(false)
    expect(looksLikePdf(Buffer.alloc(0))).toBe(false)
  })

  it('lists a chrome binary for this platform', () => {
    const names = chromeCandidates().join(' ')
    expect(names.toLowerCase()).toMatch(/chrome|chromium/)
  })
})
