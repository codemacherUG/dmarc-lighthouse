import { describe, expect, it } from 'vitest'
import {
  appendScannerNoiseEntry,
  DEFAULT_SCANNER_NOISE_HOSTS,
  hostHasDomainSuffix,
  hostMatchesScannerNoise,
  ipMatchesScannerNoise,
  matchesScannerNoise,
  parseScannerNoiseHosts,
  suggestScannerNoiseEntry
} from '../src/shared/scanner-noise'

describe('hostHasDomainSuffix', () => {
  it('matches the domain and its subdomains at label boundaries', () => {
    expect(hostHasDomainSuffix('cloud-sec-av.com', 'cloud-sec-av.com')).toBe(true)
    expect(hostHasDomainSuffix('mail.eu.cloud-sec-av.com', 'cloud-sec-av.com')).toBe(true)
    expect(hostHasDomainSuffix('CLOUD-SEC-AV.COM.', 'cloud-sec-av.com')).toBe(true)
  })

  it('does not match a shorter label inside a longer name', () => {
    expect(hostHasDomainSuffix('cloud-sec-av.com', 'av.com')).toBe(false)
    expect(hostHasDomainSuffix('notcloud-sec-av.com', 'cloud-sec-av.com')).toBe(false)
    expect(hostHasDomainSuffix('ec2.amazonaws.com', 'cloud-sec-av.com')).toBe(false)
  })
})

describe('parseScannerNoiseHosts', () => {
  it('parses the shipped default as a suffix', () => {
    expect(parseScannerNoiseHosts(DEFAULT_SCANNER_NOISE_HOSTS)).toEqual([
      { kind: 'suffix', value: 'cloud-sec-av.com' }
    ])
  })

  it('skips comments, blanks, single labels, and accepts comma-separated suffixes', () => {
    const matchers = parseScannerNoiseHosts(`
# Check Point Harmony
cloud-sec-av.com, avanan.com
com
*.example.net.
`)
    expect(matchers).toEqual([
      { kind: 'suffix', value: 'cloud-sec-av.com' },
      { kind: 'suffix', value: 'avanan.com' },
      { kind: 'suffix', value: 'example.net' }
    ])
  })

  it('accepts /regex/i and ignores invalid regex', () => {
    const matchers = parseScannerNoiseHosts('/cloud-sec-av\\.com$/i\n/(unclosed\n/valid-host\\.example$/')
    expect(matchers).toHaveLength(2)
    expect(matchers[0]?.kind).toBe('regex')
    expect(matchers[1]?.kind).toBe('regex')
  })

  it('parses IPv4 and IPv6 as ip matchers, not suffixes', () => {
    const matchers = parseScannerNoiseHosts('203.0.113.5\n2001:db8::1\ncloud-sec-av.com')
    expect(matchers).toEqual([
      { kind: 'ip', value: '203.0.113.5' },
      { kind: 'ip', value: '2001:db8::1' },
      { kind: 'suffix', value: 'cloud-sec-av.com' }
    ])
  })
})

describe('hostMatchesScannerNoise', () => {
  const defaults = parseScannerNoiseHosts(DEFAULT_SCANNER_NOISE_HOSTS)

  it('matches Harmony PTRs via the default suffix', () => {
    expect(hostMatchesScannerNoise('mail-1.eu.cloud-sec-av.com', defaults)).toBe(true)
    expect(hostMatchesScannerNoise('ec2.amazonaws.com', defaults)).toBe(false)
    expect(hostMatchesScannerNoise(null, defaults)).toBe(false)
  })

  it('matches a custom regex from the list', () => {
    const matchers = parseScannerNoiseHosts('/pphosted\\.com$/')
    expect(hostMatchesScannerNoise('mx1.pphosted.com', matchers)).toBe(true)
    expect(hostMatchesScannerNoise('mail.example.com', matchers)).toBe(false)
  })
})

describe('ipMatchesScannerNoise', () => {
  it('matches a listed IP case-insensitively and ignores host suffixes', () => {
    const matchers = parseScannerNoiseHosts('203.0.113.5\n2001:DB8::1\ncloud-sec-av.com')
    expect(ipMatchesScannerNoise('203.0.113.5', matchers)).toBe(true)
    expect(ipMatchesScannerNoise('2001:db8::1', matchers)).toBe(true)
    expect(ipMatchesScannerNoise('198.51.100.9', matchers)).toBe(false)
    expect(matchesScannerNoise('198.51.100.9', 'mail.eu.cloud-sec-av.com', matchers)).toBe(true)
  })
})

describe('suggestScannerNoiseEntry', () => {
  it('uses the organizational domain for known gateways', () => {
    expect(
      suggestScannerNoiseEntry('mail-1.eu.cloud-sec-av.com', '203.0.113.5', 'gateway')
    ).toBe('cloud-sec-av.com')
  })

  it('keeps the full PTR for non-gateway senders', () => {
    expect(suggestScannerNoiseEntry('ec2-3-5-140-1.compute-1.amazonaws.com', '3.5.140.1', 'infra')).toBe(
      'ec2-3-5-140-1.compute-1.amazonaws.com'
    )
  })

  it('falls back to the IP when no PTR is available', () => {
    expect(suggestScannerNoiseEntry(null, '203.0.113.5')).toBe('203.0.113.5')
  })
})

describe('appendScannerNoiseEntry', () => {
  it('appends a new line and skips entries already covered by a suffix', () => {
    expect(appendScannerNoiseEntry('cloud-sec-av.com', 'pphosted.com')).toBe(
      'cloud-sec-av.com\npphosted.com'
    )
    expect(appendScannerNoiseEntry('cloud-sec-av.com', 'mail.eu.cloud-sec-av.com')).toBe(
      'cloud-sec-av.com'
    )
    expect(appendScannerNoiseEntry('203.0.113.5', '203.0.113.5')).toBe('203.0.113.5')
  })
})
