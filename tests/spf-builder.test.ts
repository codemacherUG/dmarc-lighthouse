import { describe, expect, it } from 'vitest'
import {
  buildSpfRecord,
  parseSpfRecord,
  spfRecordsEquivalent,
  validateSpfBuilderStep
} from '../src/shared/spf-builder'

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
    const parsed = parseSpfRecord(
      'v=spf1 include:_spf.google.com ip4:203.0.113.0/24 mx ~all'
    )
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
})
