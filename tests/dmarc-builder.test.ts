import { describe, expect, it } from 'vitest'
import {
  buildDmarcRecord,
  defaultDmarcMailbox,
  isValidDomain,
  parseDmarcRecord,
  validateBuilderStep
} from '../src/shared/dmarc-builder'

describe('dmarc-builder', () => {
  it('validates domains', () => {
    expect(isValidDomain('example.com')).toBe(true)
    expect(isValidDomain('mail.example.co.uk')).toBe(true)
    expect(isValidDomain('localhost')).toBe(false)
    expect(isValidDomain('')).toBe(false)
  })

  it('suggests dmarc@domain for rua and ruf', () => {
    expect(defaultDmarcMailbox('Example.COM.')).toBe('dmarc@example.com')
  })

  it('builds a complete DMARC record', () => {
    const result = buildDmarcRecord({
      domain: 'Example.COM.',
      policy: 'quarantine',
      subdomainPolicy: 'reject',
      pct: 25,
      rua: 'dmarc@example.com, mailto:backup@example.com',
      ruf: 'ruf@example.com',
      fo: ['1', 'd'],
      adkim: 's',
      aspf: 'r'
    })
    expect(result.host).toBe('_dmarc.example.com')
    expect(result.type).toBe('TXT')
    expect(result.value).toBe(
      'v=DMARC1; p=quarantine; sp=reject; pct=25; rua=mailto:dmarc@example.com,mailto:backup@example.com; ruf=mailto:ruf@example.com; fo=1:d; adkim=s; aspf=r'
    )
  })

  it('omits pct when 100 and sp when same', () => {
    const result = buildDmarcRecord({
      domain: 'example.com',
      policy: 'none',
      subdomainPolicy: 'same',
      pct: 100,
      rua: 'dmarc@example.com',
      ruf: '',
      fo: ['0'],
      adkim: 'r',
      aspf: 'r'
    })
    expect(result.value).toBe(
      'v=DMARC1; p=none; rua=mailto:dmarc@example.com; adkim=r; aspf=r'
    )
  })

  it('parses an existing record into form fields', () => {
    const parsed = parseDmarcRecord(
      'v=DMARC1; p=reject; sp=quarantine; pct=50; rua=mailto:a@example.com; fo=1:s; adkim=s; aspf=s'
    )
    expect(parsed.policy).toBe('reject')
    expect(parsed.subdomainPolicy).toBe('quarantine')
    expect(parsed.pct).toBe(50)
    expect(parsed.rua).toBe('a@example.com')
    expect(parsed.fo).toEqual(['1', 's'])
    expect(parsed.adkim).toBe('s')
    expect(parsed.aspf).toBe('s')
  })

  it('validates wizard steps', () => {
    expect(
      validateBuilderStep('domain', {
        domain: '',
        policy: 'none',
        subdomainPolicy: 'same',
        pct: 100,
        rua: '',
        ruf: '',
        fo: ['0'],
        adkim: 'r',
        aspf: 'r'
      })
    ).toBe('builder.error.domain')

    expect(
      validateBuilderStep('reporting', {
        domain: 'example.com',
        policy: 'none',
        subdomainPolicy: 'same',
        pct: 100,
        rua: '',
        ruf: '',
        fo: ['0'],
        adkim: 'r',
        aspf: 'r'
      })
    ).toBe('builder.error.rua')
  })
})
