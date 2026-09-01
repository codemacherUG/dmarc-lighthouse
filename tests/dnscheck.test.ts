import { describe, expect, it, vi } from 'vitest'
import {
  ancestorZones,
  discoverDmarcRecords,
  normalizeDkimSelector,
  parseDnssecResponse,
  parseDnssecWireResponse,
  parseDmarcPolicy,
  resolveTxtRecords
} from '../src/main/dnscheck'

vi.mock('../src/main/dns-env', async () => {
  const actual = await vi.importActual<typeof import('../src/main/dns-env')>('../src/main/dns-env')
  return {
    ...actual,
    resolveTxtReliable: vi.fn(async (name: string) => {
      const directRecord = txtByHost.get(name)
      if (directRecord) return [[directRecord]]
      const zone = name.replace(/^_dmarc\./, '')
      const record = txtByZone.get(zone)
      if (!record) throw Object.assign(new Error('ENODATA'), { code: 'ENODATA' })
      return [[record]]
    })
  }
})

let txtByZone = new Map<string, string>()
let txtByHost = new Map<string, string>()

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

describe('resolveTxtRecords', () => {
  it('follows an authoritative CNAME to a TXT record in another zone', async () => {
    const target = 'selector1-example-com._domainkey.example.onmicrosoft.com'
    txtByHost = new Map([[target, 'v=DKIM1; k=rsa; p=test']])
    const auth = {
      resolveTxt: vi.fn(async () => []),
      resolveCname: vi.fn(async () => [target])
    }

    await expect(resolveTxtRecords('selector1._domainkey.example.com', auth)).resolves.toEqual([
      ['v=DKIM1; k=rsa; p=test']
    ])
  })
})

describe('ancestorZones', () => {
  it('lists the domain then parents, stopping before the TLD', () => {
    expect(ancestorZones('auto-ahlhelm.de')).toEqual(['auto-ahlhelm.de'])
    expect(ancestorZones('mail.foo.example.com')).toEqual([
      'mail.foo.example.com',
      'foo.example.com',
      'example.com'
    ])
    expect(ancestorZones('EXAMPLE.COM.')).toEqual(['example.com'])
  })
})

describe('parseDmarcPolicy', () => {
  it('extracts the legacy p/rua/ruf tags', () => {
    const parsed = parseDmarcPolicy(['v=DMARC1; p=reject; rua=mailto:a@example.com'])
    expect(parsed).toMatchObject({ policy: 'reject', rua: 'mailto:a@example.com', testing: false })
  })

  it('extracts t=, np= and psd= (RFC 9989)', () => {
    const parsed = parseDmarcPolicy(['v=DMARC1; p=quarantine; np=reject; t=y; psd=y'])
    expect(parsed).toMatchObject({ policy: 'quarantine', np: 'reject', testing: true, psd: true })
  })

  it('defaults testing/psd to false and np to null when absent', () => {
    const parsed = parseDmarcPolicy(['v=DMARC1; p=none'])
    expect(parsed).toMatchObject({ testing: false, np: null, psd: false })
  })
})

describe('parseDnssecResponse', () => {
  it('reports a DNSSEC-validated answer from the AD bit', () => {
    expect(parseDnssecResponse({ Status: 0, AD: true }, 'dns.quad9.net')).toEqual({
      status: 'validated',
      resolver: 'dns.quad9.net'
    })
  })

  it('reports successful but unsigned answers', () => {
    expect(parseDnssecResponse({ Status: 0, AD: false }, 'dns.quad9.net')).toEqual({
      status: 'unsigned',
      resolver: 'dns.quad9.net'
    })
  })

  it('keeps resolver errors distinguishable from unsigned domains', () => {
    expect(parseDnssecResponse({ Status: 2, Comment: 'Failure' }, 'dns.quad9.net')).toEqual({
      status: 'error',
      resolver: 'dns.quad9.net',
      error: 'Failure'
    })
  })
})

describe('parseDnssecWireResponse', () => {
  it('reads the AD bit from an RFC-DoH DNS response', () => {
    const response = Buffer.alloc(12)
    response.writeUInt16BE(0x8020, 2)
    expect(parseDnssecWireResponse(response, 'dns.quad9.net')).toEqual({
      status: 'validated',
      resolver: 'dns.quad9.net'
    })
  })

  it('keeps DNS errors distinct from unsigned zones', () => {
    const response = Buffer.alloc(12)
    response.writeUInt16BE(0x8002, 2)
    expect(parseDnssecWireResponse(response, 'dns.quad9.net')).toEqual({
      status: 'error',
      resolver: 'dns.quad9.net',
      error: 'DNS response status 2'
    })
  })
})

describe('discoverDmarcRecords', () => {
  it('uses the exact domain record when present', async () => {
    txtByZone = new Map([['mail.example.com', 'v=DMARC1; p=reject']])
    const result = await discoverDmarcRecords('mail.example.com', null)
    expect(result).toMatchObject({ zone: 'mail.example.com', treeWalked: false })
    expect(result.records).toEqual(['v=DMARC1; p=reject'])
  })

  it('walks up to the organizational domain when the subdomain has no record', async () => {
    txtByZone = new Map([['example.com', 'v=DMARC1; p=quarantine']])
    const result = await discoverDmarcRecords('mail.example.com', null)
    expect(result).toMatchObject({ zone: 'example.com', treeWalked: true })
    expect(result.records).toEqual(['v=DMARC1; p=quarantine'])
  })

  it('reports no record found after walking the whole chain', async () => {
    txtByZone = new Map()
    const result = await discoverDmarcRecords('mail.foo.example.com', null)
    expect(result.records).toEqual([])
    expect(result.zone).toBe('mail.foo.example.com')
  })
})
