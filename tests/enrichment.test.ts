import { describe, expect, it } from 'vitest'
import { isListedDnsblAnswer, reverseIpForDnsbl } from '../src/main/dnsbl'
import { rdapIpPathSegment } from '../src/main/rdap'
import { matchCloudProvider, parseCidr, type CloudPrefix } from '../src/shared/ipcidr'
import {
  buildDomainStats,
  buildProblemSources,
  DOMAIN_HEALTH_WINDOW_DAYS,
  filterReportsLastDays,
  isHealthyDmarcOutcome,
  mergeDomainHealth,
  reportsForDomainHealth
} from '../src/shared/analyze'
import {
  isAuthorizedSender,
  normalizeAuthorizedSenderEntry,
  parseAuthorizedSenderPrefixes
} from '../src/shared/ipcidr'
import type { DnsCheckResult, ReportRow, SerializedRecord } from '../src/shared/types'

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
    dkimSelectors: ['s1'],
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

function dns(overrides: Partial<DnsCheckResult> = {}): DnsCheckResult {
  return {
    domain: 'example.com',
    dmarc: {
      found: true,
      records: ['v=DMARC1; p=reject'],
      policy: 'reject',
      rua: null,
      ruf: null
    },
    spf: { found: true, records: ['v=spf1 -all'] },
    dkim: { selectors: [{ selector: 's1', found: true, record: 'v=DKIM1; p=abc' }] },
    checkedAt: new Date().toISOString(),
    ...overrides
  }
}

describe('reverseIpForDnsbl', () => {
  it('reverses IPv4 octets', () => {
    expect(reverseIpForDnsbl('203.0.113.15')).toBe('15.113.0.203')
  })

  it('expands and reverses IPv6 to nibbles', () => {
    const rev = reverseIpForDnsbl('2001:db8::1')
    expect(rev).toBeTruthy()
    expect(rev!.startsWith('1.0.0.0')).toBe(true)
    expect(rev!.endsWith('8.b.d.0.1.0.0.2')).toBe(true)
  })

  it('returns null for invalid input', () => {
    expect(reverseIpForDnsbl('not-an-ip')).toBeNull()
  })
})

describe('isListedDnsblAnswer', () => {
  it('accepts real Spamhaus ZEN listing codes', () => {
    expect(isListedDnsblAnswer(['127.0.0.2'])).toBe(true)
    expect(isListedDnsblAnswer(['127.0.0.10'])).toBe(true)
  })

  it('rejects Spamhaus public-resolver / policy error codes', () => {
    expect(isListedDnsblAnswer(['127.255.255.254'])).toBe(false)
    expect(isListedDnsblAnswer(['127.255.255.255'])).toBe(false)
    expect(isListedDnsblAnswer(['127.255.255.252'])).toBe(false)
  })

  it('rejects empty or non-127 answers', () => {
    expect(isListedDnsblAnswer([])).toBe(false)
    expect(isListedDnsblAnswer(['8.8.8.8'])).toBe(false)
  })
})

describe('cloud ranges prefix match', () => {
  it('parses IPv4 CIDR and matches longest prefix', () => {
    const prefixes: CloudPrefix[] = [
      parseCidr('Amazon AWS', '192.0.2.0/24')!,
      parseCidr('Amazon SES', '192.0.2.0/28')!
    ]
    expect(matchCloudProvider('192.0.2.5', prefixes)).toBe('Amazon SES')
    expect(matchCloudProvider('198.51.100.1', prefixes)).toBeNull()
  })

  it('matches IPv6 CIDR', () => {
    const prefixes: CloudPrefix[] = [parseCidr('Google', '2001:db8::/32')!]
    expect(matchCloudProvider('2001:db8:1::10', prefixes)).toBe('Google')
    expect(matchCloudProvider('2001:db9::1', prefixes)).toBeNull()
  })
})

describe('domain health / Ampel', () => {
  it('aggregates domain stats and selectors', () => {
    const stats = buildDomainStats([
      report({
        domain: 'Example.COM',
        records: [
          record({ count: 8, passesDmarc: true, dkimSelectors: ['s1'] }),
          record({ count: 2, passesDmarc: false, dkimSelectors: ['s2'] })
        ]
      }),
      report({ domain: 'other.org', records: [record({ count: 1, passesDmarc: true })] })
    ])
    expect(stats[0]?.domain).toBe('example.com')
    expect(stats[0]?.total).toBe(10)
    expect(stats[0]?.passing).toBe(8)
    expect(stats[0]?.dkimSelectors).toEqual(['s1', 's2'])
  })

  it('marks ok for reject + high pass rate + SPF', () => {
    const stats = buildDomainStats([
      report({
        records: [record({ count: 100, passesDmarc: true })]
      })
    ])[0]!
    const health = mergeDomainHealth(stats, dns())
    expect(health.status).toBe('ok')
    expect(health.reasons).toContain('health.reason.ok')
  })

  it('marks bad without DMARC or SPF or low pass rate', () => {
    const low = buildDomainStats([
      report({
        records: [
          record({ count: 50, passesDmarc: true }),
          record({ count: 50, passesDmarc: false })
        ]
      })
    ])[0]!
    expect(mergeDomainHealth(low, dns()).status).toBe('bad')

    const noDmarc = buildDomainStats([report()])[0]!
    expect(
      mergeDomainHealth(
        noDmarc,
        dns({
          dmarc: { found: false, records: [], policy: null, rua: null, ruf: null }
        })
      ).status
    ).toBe('bad')
  })

  it('marks warn for p=none with good pass rate', () => {
    const stats = buildDomainStats([
      report({ records: [record({ count: 100, passesDmarc: true })] })
    ])[0]!
    const health = mergeDomainHealth(
      stats,
      dns({
        dmarc: {
          found: true,
          records: ['v=DMARC1; p=none'],
          policy: 'none',
          rua: null,
          ruf: null
        }
      })
    )
    expect(health.status).toBe('warn')
    expect(health.reasons).toContain('health.reason.policyNone')
  })

  it('returns unknown without DNS', () => {
    const stats = buildDomainStats([report()])[0]!
    expect(mergeDomainHealth(stats, null).status).toBe('unknown')
  })

  it(`uses only the last ${DOMAIN_HEALTH_WINDOW_DAYS} days for Ampel volume`, () => {
    const now = new Date()
    const recent = new Date(now)
    recent.setDate(recent.getDate() - 3)
    const old = new Date(now)
    old.setDate(old.getDate() - (DOMAIN_HEALTH_WINDOW_DAYS + 5))

    const rows = [
      report({
        reportId: 'recent',
        dateBegin: recent.toISOString(),
        dateEnd: recent.toISOString(),
        records: [record({ count: 10, passesDmarc: true })]
      }),
      report({
        reportId: 'old',
        dateBegin: old.toISOString(),
        dateEnd: old.toISOString(),
        records: [record({ count: 90, passesDmarc: false })]
      })
    ]

    const windowed = reportsForDomainHealth(rows)
    expect(windowed.map((r) => r.reportId)).toEqual(['recent'])
    expect(filterReportsLastDays(rows, DOMAIN_HEALTH_WINDOW_DAYS)).toHaveLength(1)

    const stats = buildDomainStats(windowed)[0]!
    expect(stats.total).toBe(10)
    expect(stats.passRate).toBe(100)
  })

  it('treats reject/quarantine auth-fails as healthy (policy working)', () => {
    expect(
      isHealthyDmarcOutcome(
        record({ passesDmarc: false, disposition: 'reject', dkimResult: 'fail', spfResult: 'fail' })
      )
    ).toBe(true)
    expect(
      isHealthyDmarcOutcome(
        record({
          passesDmarc: false,
          disposition: 'quarantine',
          dkimResult: 'fail',
          spfResult: 'fail'
        })
      )
    ).toBe(true)

    const stats = buildDomainStats([
      report({
        records: [
          record({ count: 9, passesDmarc: true }),
          record({
            count: 1,
            passesDmarc: false,
            disposition: 'reject',
            dkimResult: 'fail',
            spfResult: 'fail'
          })
        ]
      })
    ])[0]!
    expect(stats.total).toBe(10)
    expect(stats.passing).toBe(10)
    expect(stats.passRate).toBe(100)
    expect(mergeDomainHealth(stats, dns()).status).toBe('ok')
  })

  it('treats local_policy overrides as healthy (e.g. Google ARC)', () => {
    const rec = record({
      passesDmarc: false,
      disposition: 'none',
      dkimResult: 'fail',
      spfResult: 'fail',
      reasons: [{ type: 'local_policy', comment: 'arc=pass' }]
    })
    expect(isHealthyDmarcOutcome(rec)).toBe(true)

    const stats = buildDomainStats([report({ records: [rec] })])[0]!
    expect(stats.passRate).toBe(100)
  })

  it('still treats delivered auth-fails (disposition none) as unhealthy', () => {
    expect(
      isHealthyDmarcOutcome(
        record({ passesDmarc: false, disposition: 'none', dkimResult: 'fail', spfResult: 'fail' })
      )
    ).toBe(false)
  })
})

describe('problem sources (rollout)', () => {
  it('lists delivered auth-fails with SPF/DKIM fail counts', () => {
    const rows = buildProblemSources([
      report({
        records: [
          record({
            sourceIp: '192.0.2.10',
            count: 5,
            passesDmarc: false,
            disposition: 'none',
            spfResult: 'fail',
            dkimResult: 'fail',
            headerFrom: 'mail.example.com'
          }),
          record({
            sourceIp: '192.0.2.10',
            count: 2,
            passesDmarc: false,
            disposition: 'none',
            spfResult: 'fail',
            dkimResult: 'pass',
            headerFrom: 'newsletter.example.com'
          }),
          record({
            sourceIp: '198.51.100.1',
            count: 1,
            passesDmarc: false,
            disposition: 'none',
            spfResult: 'fail',
            dkimResult: 'fail',
            headerFrom: 'other.example.com'
          })
        ]
      })
    ])

    expect(rows).toHaveLength(2)
    expect(rows[0]).toMatchObject({
      sourceIp: '192.0.2.10',
      count: 7,
      spfFail: 7,
      dkimFail: 5,
      headerFrom: 'mail.example.com'
    })
    expect(rows[1]?.sourceIp).toBe('198.51.100.1')
  })

  it('excludes reject fails and local_policy overrides', () => {
    const rows = buildProblemSources([
      report({
        records: [
          record({
            sourceIp: '192.0.2.50',
            count: 3,
            passesDmarc: false,
            disposition: 'reject',
            spfResult: 'fail',
            dkimResult: 'fail'
          }),
          record({
            sourceIp: '192.0.2.51',
            count: 2,
            passesDmarc: false,
            disposition: 'none',
            spfResult: 'fail',
            dkimResult: 'fail',
            reasons: [{ type: 'local_policy', comment: 'arc=pass' }]
          }),
          record({
            sourceIp: '192.0.2.52',
            count: 1,
            passesDmarc: false,
            disposition: 'none',
            spfResult: 'fail',
            dkimResult: 'fail'
          })
        ]
      })
    ])

    expect(rows).toHaveLength(1)
    expect(rows[0]?.sourceIp).toBe('192.0.2.52')
    expect(rows[0]?.count).toBe(1)
  })

  it('ignores auth-pass rows', () => {
    expect(
      buildProblemSources([
        report({
          records: [record({ sourceIp: '192.0.2.1', count: 10, passesDmarc: true })]
        })
      ])
    ).toEqual([])
  })

  it('lists all unhealthy IPs without sender scoping', () => {
    const rows = buildProblemSources([
      report({
        records: [
          record({
            sourceIp: '192.0.2.10',
            count: 3,
            passesDmarc: false,
            disposition: 'none',
            spfResult: 'fail',
            dkimResult: 'fail'
          }),
          record({
            sourceIp: '198.51.100.9',
            count: 5,
            passesDmarc: false,
            disposition: 'none',
            spfResult: 'fail',
            dkimResult: 'fail'
          })
        ]
      })
    ])
    expect(rows).toHaveLength(2)
    expect(rows.map((r) => r.sourceIp).sort()).toEqual(['192.0.2.10', '198.51.100.9'])
  })
})

describe('ipcidr sender matching', () => {
  it('normalizes bare IPs to CIDR', () => {
    expect(normalizeAuthorizedSenderEntry('203.0.113.5')).toBe('203.0.113.5/32')
    expect(normalizeAuthorizedSenderEntry('2001:db8::1')).toBe('2001:db8::1/128')
    expect(normalizeAuthorizedSenderEntry('not-an-ip')).toBeNull()
  })

  it('matches IPs against CIDR prefixes', () => {
    const prefixes = parseAuthorizedSenderPrefixes(['192.0.2.10', '2001:db8:1::/48'])
    expect(isAuthorizedSender('192.0.2.10', prefixes)).toBe(true)
    expect(isAuthorizedSender('192.0.2.11', prefixes)).toBe(false)
    expect(isAuthorizedSender('2001:db8:1::abcd', prefixes)).toBe(true)
    expect(isAuthorizedSender('2001:db8:2::1', prefixes)).toBe(false)
  })
})

describe('rdapIpPathSegment', () => {
  it('keeps IPv6 colons literal (encodeURIComponent alone breaks RDAP)', () => {
    expect(rdapIpPathSegment('2a00:1450:4001:827::200e')).toBe('2a00:1450:4001:827::200e')
    expect(rdapIpPathSegment('2001:db8::1')).toBe('2001:db8::1')
  })

  it('accepts IPv4 unchanged', () => {
    expect(rdapIpPathSegment('8.8.8.8')).toBe('8.8.8.8')
  })

  it('strips IPv6 zone ids and rejects garbage', () => {
    expect(rdapIpPathSegment('fe80::1%eth0')).toBe('fe80::1')
    expect(rdapIpPathSegment('not-an-ip')).toBeNull()
    expect(rdapIpPathSegment('')).toBeNull()
  })
})
