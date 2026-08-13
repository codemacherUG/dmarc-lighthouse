import { describe, expect, it } from 'vitest'
import { normalizeDkimSelector } from '../src/main/dnscheck'

describe('normalizeDkimSelector', () => {
  it('keeps a bare selector', () => {
    expect(normalizeDkimSelector('default')).toBe('default')
    expect(normalizeDkimSelector(' google ')).toBe('google')
    expect(normalizeDkimSelector('selector1')).toBe('selector1')
  })

  it('strips ._domainkey and a full hostname', () => {
    expect(normalizeDkimSelector('default._domainkey')).toBe('default')
    expect(normalizeDkimSelector('default._domainkey.')).toBe('default')
    expect(normalizeDkimSelector('default._domainkey.auto-ahlhelm.de')).toBe('default')
    expect(normalizeDkimSelector('default._domainkey.auto-ahlhelm.de.')).toBe('default')
  })

  it('rejects empty or invalid input', () => {
    expect(normalizeDkimSelector('')).toBeNull()
    expect(normalizeDkimSelector('._domainkey')).toBeNull()
    expect(normalizeDkimSelector('_domainkey.example.com')).toBeNull()
    expect(normalizeDkimSelector('bad selector')).toBeNull()
  })
})
