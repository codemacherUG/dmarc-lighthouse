import { generateKeyPairSync } from 'crypto'
import { describe, expect, it, vi } from 'vitest'
import {
  ancestorZones,
  discoverDmarcRecords,
  inspectDkimRecord,
  normalizeDkimSelector,
  parseDnssecResponse,
  parseDnssecWireResponse,
  parseDmarcPolicy,
  resolveMxRecords,
  resolveTxtRecords
} from '../src/main/dnscheck'
import { selectorsForDnsCheck } from '../src/shared/dkim-selector'
import { resolveMxReliable } from '../src/main/dns-env'

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
    }),
    resolveMxReliable: vi.fn(async () => [
      { exchange: 'mx2.example.com.', priority: 20 },
      { exchange: 'mx1.example.com.', priority: 10 }
    ])
  }
})

let txtByZone = new Map<string, string>()
let txtByHost = new Map<string, string>()

describe('resolveMxRecords', () => {
  it('queries the recursive resolver when no authoritative resolver is available', async () => {
    await expect(resolveMxRecords('example.com', null)).resolves.toEqual([
      { exchange: 'mx1.example.com', priority: 10 },
      { exchange: 'mx2.example.com', priority: 20 }
    ])
    expect(resolveMxReliable).toHaveBeenCalledWith('example.com')
  })

  it('uses authoritative MX records and orders them by preference', async () => {
    const auth = {
      resolveTxt: vi.fn(async () => []),
      resolveCname: vi.fn(async () => []),
      resolveMx: vi.fn(async () => [
        { exchange: 'backup.example.com.', priority: 20 },
        { exchange: 'Mail.Example.com.', priority: 10 }
      ])
    }

    await expect(resolveMxRecords('example.com', auth)).resolves.toEqual([
      { exchange: 'mail.example.com', priority: 10 },
      { exchange: 'backup.example.com', priority: 20 }
    ])
    expect(auth.resolveMx).toHaveBeenCalledWith('example.com')
  })

  it('falls back to the recursive resolver when the authoritative query fails', async () => {
    vi.mocked(resolveMxReliable).mockClear()
    const auth = {
      resolveTxt: vi.fn(async () => []),
      resolveCname: vi.fn(async () => []),
      resolveMx: vi.fn(async () => {
        throw new Error('authoritative server unavailable')
      })
    }

    await expect(resolveMxRecords('example.com', auth)).resolves.toEqual([
      { exchange: 'mx1.example.com', priority: 10 },
      { exchange: 'mx2.example.com', priority: 20 }
    ])
    expect(resolveMxReliable).toHaveBeenCalledWith('example.com')
  })

  it('treats a domain without MX data as an empty result', async () => {
    const auth = {
      resolveTxt: vi.fn(async () => []),
      resolveCname: vi.fn(async () => []),
      resolveMx: vi.fn(async () => {
        throw Object.assign(new Error('No data'), { code: 'ENODATA' })
      })
    }

    await expect(resolveMxRecords('example.com', auth)).resolves.toEqual([])
  })
})

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

describe('selectorsForDnsCheck', () => {
  it('uses the enabled domain selectors before selectors from reports', () => {
    expect(
      selectorsForDnsCheck(
        [],
        [
          { selector: 'dkim', enabled: true },
          { selector: 'mail4', enabled: false }
        ],
        ['dkim', 'mail4', 'mail8']
      )
    ).toEqual(['dkim'])
  })

  it('uses report selectors when no domain settings exist', () => {
    expect(selectorsForDnsCheck([], [], ['dkim', 'mail4'])).toEqual(['dkim', 'mail4'])
  })

  it('lets explicitly entered selectors override domain settings', () => {
    expect(
      selectorsForDnsCheck(['manual'], [{ selector: 'mail4', enabled: false }], ['dkim'])
    ).toEqual(['manual'])
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

describe('inspectDkimRecord', () => {
  it('treats an empty p= tag as a revoked key (found: false, revoked: true)', () => {
    const info = inspectDkimRecord('v=DKIM1; k=rsa; p=')
    expect(info).toMatchObject({
      found: false,
      revoked: true,
      keyType: 'rsa',
      keyBits: null,
      weakKey: false,
      testing: false
    })
  })

  it('extracts RSA modulus bit length, weak-key flag and t=y testing mode', () => {
    const { publicKey: pub1024 } = generateKeyPairSync('rsa', { modulusLength: 1024 })
    const b64_1024 = (pub1024.export({ type: 'spki', format: 'der' }) as Buffer).toString('base64')
    expect(inspectDkimRecord(`v=DKIM1; k=rsa; t=y:s; p=${b64_1024}`)).toEqual({
      found: true,
      revoked: false,
      keyType: 'rsa',
      keyBits: 1024,
      weakKey: true,
      testing: true
    })

    const { publicKey: pub2048 } = generateKeyPairSync('rsa', { modulusLength: 2048 })
    const b64_2048 = (pub2048.export({ type: 'spki', format: 'der' }) as Buffer).toString('base64')
    expect(inspectDkimRecord(`v=DKIM1; p=${b64_2048}`)).toEqual({
      found: true,
      revoked: false,
      keyType: 'rsa',
      keyBits: 2048,
      weakKey: false,
      testing: false
    })
  })

  it('recognizes ed25519 256-bit keys', () => {
    const raw32 = Buffer.alloc(32, 7).toString('base64')
    expect(inspectDkimRecord(`v=DKIM1; k=ed25519; p=${raw32}`)).toEqual({
      found: true,
      revoked: false,
      keyType: 'ed25519',
      keyBits: 256,
      weakKey: false,
      testing: false
    })
  })
})
