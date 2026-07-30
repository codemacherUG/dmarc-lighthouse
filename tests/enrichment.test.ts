import { describe, expect, it } from 'vitest'
import { isListedDnsblAnswer, reverseIpForDnsbl } from '../src/main/dnsbl'
import { matchCloudProvider, parseCidr, type CloudPrefix } from '../src/shared/ipcidr'
import { buildDomainStats, mergeDomainHealth } from '../src/shared/analyze'
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
})
