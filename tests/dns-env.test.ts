import { describe, expect, it, beforeEach } from 'vitest'
import {
  isUsableDnsServer,
  normalizeDnsServer,
  pickDnsServers,
  PUBLIC_DNS_FALLBACK,
  resetDnsEnvironmentForTests
} from '../src/main/dns-env'
import { formatNetworkError } from '../src/main/network-error'

describe('normalizeDnsServer', () => {
  it('strips Windows zone ids', () => {
    expect(normalizeDnsServer('fe80::1%12')).toBe('fe80::1')
    expect(normalizeDnsServer(' 1.1.1.1 ')).toBe('1.1.1.1')
  })
})

describe('isUsableDnsServer', () => {
  it('accepts normal recursive resolvers', () => {
    expect(isUsableDnsServer('1.1.1.1')).toBe(true)
    expect(isUsableDnsServer('8.8.8.8')).toBe(true)
    expect(isUsableDnsServer('2001:4860:4860::8888')).toBe(true)
    expect(isUsableDnsServer('10.0.2.3')).toBe(true)
  })

  it('rejects link-local and deprecated site-local IPv6', () => {
    expect(isUsableDnsServer('fe80::1')).toBe(false)
    expect(isUsableDnsServer('fe80::1%eth0')).toBe(false)
    expect(isUsableDnsServer('fec0:0:0:ffff::1')).toBe(false)
    expect(isUsableDnsServer('fec0:0:0:ffff::2')).toBe(false)
    expect(isUsableDnsServer('0.0.0.0')).toBe(false)
    expect(isUsableDnsServer('::')).toBe(false)
  })
})

describe('pickDnsServers', () => {
  beforeEach(() => {
    resetDnsEnvironmentForTests()
  })

  it('filters unusable entries and prefers IPv4', () => {
    expect(
      pickDnsServers(['fec0:0:0:ffff::1', 'fe80::1%12', '10.0.2.3', '2001:db8::1'])
    ).toEqual(['10.0.2.3', '2001:db8::1'])
  })

  it('falls back to public resolvers when nothing usable remains', () => {
    expect(pickDnsServers(['fe80::1', 'fec0:0:0:ffff::1'])).toEqual([...PUBLIC_DNS_FALLBACK])
  })
})

describe('formatNetworkError', () => {
  it('unwraps nested cause chains from undici-style failures', () => {
    const leaf = Object.assign(new Error('unable to verify the first certificate'), {
      code: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE'
    })
    const mid = new Error('fetch failed')
    mid.cause = leaf
    expect(formatNetworkError(mid)).toContain('fetch failed')
    expect(formatNetworkError(mid)).toContain('UNABLE_TO_VERIFY_LEAF_SIGNATURE')
    expect(formatNetworkError(mid)).toContain('unable to verify the first certificate')
  })

  it('handles plain strings and empty input', () => {
    expect(formatNetworkError('boom')).toBe('boom')
    expect(formatNetworkError(null)).toBe('Unknown network error')
  })
})
