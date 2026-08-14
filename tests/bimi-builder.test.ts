import { describe, expect, it } from 'vitest'
import {
  bimiDmarcPrereq,
  bimiHost,
  bimiRecordsEquivalent,
  buildBimiRecord,
  isValidBimiSelector,
  normalizeBimiHttpsUrl,
  normalizeBimiSelector,
  parseBimiBuilderRecord,
  parseBimiRecord,
  validateBimiBuilderStep
} from '../src/shared/bimi-builder'

describe('bimi-builder', () => {
  it('normalizes selectors and hostnames', () => {
    expect(normalizeBimiSelector('')).toBe('default')
    expect(normalizeBimiSelector(' Brand ')).toBe('brand')
    expect(normalizeBimiSelector('brand._bimi')).toBe('brand')
    expect(normalizeBimiSelector('brand._bimi.example.com.')).toBe('brand')
    expect(bimiHost('Example.COM.', 'default')).toBe('default._bimi.example.com')
    expect(isValidBimiSelector('default')).toBe(true)
    expect(isValidBimiSelector('brand-1')).toBe(true)
    expect(isValidBimiSelector('bad selector')).toBe(false)
  })

  it('accepts only https logo and VMC URLs', () => {
    expect(normalizeBimiHttpsUrl('https://example.com/logo.svg')).toBe(
      'https://example.com/logo.svg'
    )
    expect(normalizeBimiHttpsUrl('http://example.com/logo.svg')).toBeNull()
    expect(normalizeBimiHttpsUrl('ftp://example.com/logo.svg')).toBeNull()
    expect(normalizeBimiHttpsUrl('not-a-url')).toBeNull()
  })

  it('builds a TXT record with optional VMC', () => {
    const result = buildBimiRecord({
      domain: 'Example.COM.',
      selector: 'Default',
      location: 'https://example.com/logo.svg',
      authority: 'https://example.com/vmc.pem'
    })
    expect(result.host).toBe('default._bimi.example.com')
    expect(result.type).toBe('TXT')
    expect(result.value).toBe(
      'v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem'
    )
  })

  it('omits a= when no VMC is given', () => {
    const result = buildBimiRecord({
      domain: 'example.com',
      selector: 'default',
      location: 'https://cdn.example.com/bimi.svg',
      authority: ''
    })
    expect(result.value).toBe('v=BIMI1; l=https://cdn.example.com/bimi.svg')
    expect(result.tags.map((t) => t.key)).toEqual(['v', 'l'])
  })

  it('parses an existing record into form fields', () => {
    const parsed = parseBimiBuilderRecord(
      'v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem'
    )
    expect(parsed.location).toBe('https://example.com/logo.svg')
    expect(parsed.authority).toBe('https://example.com/vmc.pem')
    expect(parseBimiRecord('v=spf1 -all').found).toBe(false)
  })

  it('treats equivalent records as equal regardless of tag spacing', () => {
    expect(
      bimiRecordsEquivalent(
        'v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem',
        'v=BIMI1;l=https://example.com/logo.svg;a=https://example.com/vmc.pem'
      )
    ).toBe(true)
    expect(
      bimiRecordsEquivalent(
        'v=BIMI1; l=https://example.com/logo.svg',
        'v=BIMI1; l=https://example.com/other.svg'
      )
    ).toBe(false)
  })

  it('requires quarantine/reject at pct=100 for BIMI', () => {
    expect(bimiDmarcPrereq(null, []).reason).toBe('missing')
    expect(bimiDmarcPrereq('none', ['v=DMARC1; p=none']).reason).toBe('policy')
    expect(bimiDmarcPrereq('reject', ['v=DMARC1; p=reject; pct=50']).reason).toBe('pct')
    expect(bimiDmarcPrereq('quarantine', ['v=DMARC1; p=quarantine']).ok).toBe(true)
    expect(bimiDmarcPrereq('reject', ['v=DMARC1; p=reject']).ok).toBe(true)
  })

  it('validates wizard steps', () => {
    expect(
      validateBimiBuilderStep('domain', {
        domain: '',
        selector: 'default',
        location: '',
        authority: ''
      })
    ).toBe('bimiBuilder.error.domain')

    expect(
      validateBimiBuilderStep('logo', {
        domain: 'example.com',
        selector: 'bad selector',
        location: 'https://example.com/logo.svg',
        authority: ''
      })
    ).toBe('bimiBuilder.error.selector')

    expect(
      validateBimiBuilderStep('logo', {
        domain: 'example.com',
        selector: 'default',
        location: 'http://example.com/logo.svg',
        authority: ''
      })
    ).toBe('bimiBuilder.error.location')

    expect(
      validateBimiBuilderStep('logo', {
        domain: 'example.com',
        selector: 'default',
        location: 'https://example.com/logo.svg',
        authority: 'http://example.com/vmc.pem'
      })
    ).toBe('bimiBuilder.error.authority')

    expect(
      validateBimiBuilderStep('logo', {
        domain: 'example.com',
        selector: 'default',
        location: 'https://example.com/logo.svg',
        authority: ''
      })
    ).toBeNull()
  })
})
