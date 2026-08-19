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
    expect(result.value).toBe('v=DMARC1; p=none; rua=mailto:dmarc@example.com; adkim=r; aspf=r')
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

  it('emits t=y for a testing rollout and warns about legacy pct', () => {
    const tested = buildDmarcRecord({
      domain: 'example.com',
      policy: 'quarantine',
      subdomainPolicy: 'same',
      nonexistentSubdomainPolicy: 'same',
      pct: 100,
      testing: true,
      psd: false,
      rua: 'dmarc@example.com',
      ruf: '',
      fo: ['0'],
      adkim: 'r',
      aspf: 'r'
    })
    expect(tested.value).toContain('t=y')
    expect(tested.warnings).toEqual([])

    const legacy = buildDmarcRecord({
      domain: 'example.com',
      policy: 'quarantine',
      subdomainPolicy: 'same',
      nonexistentSubdomainPolicy: 'same',
      pct: 25,
      testing: false,
      psd: false,
      rua: 'dmarc@example.com',
      ruf: '',
      fo: ['0'],
      adkim: 'r',
      aspf: 'r'
    })
    expect(legacy.value).toContain('pct=25')
    expect(legacy.warnings).toEqual(['builder.warning.pctDeprecated'])
  })

  it('emits np= and psd= when set', () => {
    const result = buildDmarcRecord({
      domain: 'example.com',
      policy: 'reject',
      subdomainPolicy: 'same',
      nonexistentSubdomainPolicy: 'reject',
      pct: 100,
      testing: false,
      psd: true,
      rua: 'dmarc@example.com',
      ruf: '',
      fo: ['0'],
      adkim: 'r',
      aspf: 'r'
    })
    expect(result.value).toBe(
      'v=DMARC1; p=reject; np=reject; rua=mailto:dmarc@example.com; adkim=r; aspf=r; psd=y'
    )
  })

  it('parses t, np and psd back from a record', () => {
    const parsed = parseDmarcRecord('v=DMARC1; p=reject; np=quarantine; t=y; psd=y')
    expect(parsed.nonexistentSubdomainPolicy).toBe('quarantine')
    expect(parsed.testing).toBe(true)
    expect(parsed.psd).toBe(true)
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
