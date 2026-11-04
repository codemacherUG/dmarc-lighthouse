import { describe, expect, it } from 'vitest'
import {
  buildSpfRecord,
  parseSpfRecord,
  spfRecordsEquivalent,
  validateSpfBuilderStep,
  validateSpfRecordSyntax
} from '../src/shared/spf-builder'
import { mergeDomainHealth } from '../src/shared/analyze'

describe('spf-builder', () => {
  it('builds a record from includes, IPs and all', () => {
    const result = buildSpfRecord({
      domain: 'Example.COM.',
      includes: ['_spf.google.com', 'include:spf.protection.outlook.com'],
      ip4: ['203.0.113.5', '198.51.100.0/24'],
      ip6: ['2001:db8::1'],
      useA: true,
      useMx: false,
      all: '-all'
    })
    expect(result.host).toBe('@')
    expect(result.type).toBe('TXT')
    expect(result.value).toBe(
      'v=spf1 include:_spf.google.com include:spf.protection.outlook.com ip4:203.0.113.5 ip4:198.51.100.0/24 ip6:2001:db8::1 a -all'
    )
  })

  it('parses an existing SPF record', () => {
    const parsed = parseSpfRecord('v=spf1 include:_spf.google.com ip4:203.0.113.0/24 mx ~all')
    expect(parsed.includes).toEqual(['_spf.google.com'])
    expect(parsed.ip4).toEqual(['203.0.113.0/24'])
    expect(parsed.useMx).toBe(true)
    expect(parsed.useA).toBe(false)
    expect(parsed.all).toBe('~all')
  })

  it('treats +qualifiers and mechanism order as equivalent', () => {
    expect(
      spfRecordsEquivalent(
        'v=spf1 include:spf.protection.outlook.com a mx -all',
        'v=spf1 +a +mx include:spf.protection.outlook.com -all'
      )
    ).toBe(true)
    expect(
      spfRecordsEquivalent(
        'v=spf1 include:spf.protection.outlook.com a mx -all',
        'v=spf1 include:spf.protection.outlook.com a mx ~all'
      )
    ).toBe(false)
  })

  it('requires domain and at least one mechanism', () => {
    expect(
      validateSpfBuilderStep('domain', {
        domain: '',
        includes: [],
        ip4: [],
        ip6: [],
        useA: false,
        useMx: false,
        all: '-all'
      })
    ).toBe('spfBuilder.error.domain')

    expect(
      validateSpfBuilderStep('mechanisms', {
        domain: 'example.com',
        includes: [],
        ip4: [],
        ip6: [],
        useA: false,
        useMx: false,
        all: '-all'
      })
    ).toBe('spfBuilder.error.mechanisms')

    expect(
      validateSpfBuilderStep('mechanisms', {
        domain: 'example.com',
        includes: ['_spf.google.com'],
        ip4: [],
        ip6: [],
        useA: false,
        useMx: false,
        all: '-all'
      })
    ).toBeNull()
  })

  it('detects RFC 7208 syntax errors such as bare hostnames and marks domain health bad', () => {
    expect(
      validateSpfRecordSyntax(
        'v=spf1 include:spf.protection.outlook.com a mx mail.xa0.serverdomain.org -all'
      )
    ).toEqual(['mail.xa0.serverdomain.org'])

    expect(
      validateSpfRecordSyntax(
        'v=spf1 a:outbound.ib-lsa.de include:spf.mail.s-web.de ip4:217.110.196.234 ~all'
      )
    ).toEqual([])

    const health = mergeDomainHealth(
      {
        domain: 'impetuum.de',
        total: 100,
        passing: 100,
        failing: 0,
        passRate: 100,
        dkimSelectors: ['selector1']
      },
      {
        domain: 'impetuum.de',
        checkedAt: '2026-11-04T10:00:00.000Z',
        dmarc: {
          found: true,
          records: ['v=DMARC1; p=reject; rua=mailto:dmarc@codemacher.de'],
          policy: 'reject',
          rua: 'mailto:dmarc@codemacher.de',
          ruf: null
        },
        spf: {
          found: true,
          records: ['v=spf1 include:spf.protection.outlook.com a mx mail.xa0.serverdomain.org -all']
        },
        dkim: {
          selectors: [{ selector: 'selector1', found: true, record: 'v=DKIM1; p=abc' }]
        }
      }
    )

    expect(health.spfOk).toBe(false)
    expect(health.status).toBe('bad')
    expect(health.reasons).toContain('health.reason.spfInvalid')
  })
})
