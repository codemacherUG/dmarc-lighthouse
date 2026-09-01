import { afterEach, describe, expect, it } from 'vitest'
import { parseCidr } from '../src/shared/ipcidr'
import type { IpInfo } from '../src/shared/types'
import { formatIpMetaHtml } from '../src/renderer/src/format'
import { state } from '../src/renderer/src/state'

afterEach(() => {
  state.ipLabelCache.clear()
  state.spfPrefixes = []
  state.sendingServices = []
})

describe('formatIpMetaHtml', () => {
  it('adds explanatory tooltips to IP metadata tags', () => {
    const ip = '203.0.113.10'
    const prefix = parseCidr('test', '203.0.113.0/24')
    if (!prefix) throw new Error('Expected a valid test CIDR')
    state.spfPrefixes = [prefix]
    state.ipLabelCache.set(ip, {
      ip,
      ptr: 'mail.example.test',
      provider: 'Example Mail',
      senderKind: 'esp',
      country: 'Deutschland',
      countryCode: 'DE',
      city: 'Berlin',
      lat: 52.52,
      lon: 13.405,
      asn: 64500,
      asOrg: 'Example Network',
      cloudProvider: 'Example Cloud',
      dnsblHits: ['example-bl', 'dnswl'],
      geoSource: 'online'
    } satisfies IpInfo)

    const html = formatIpMetaHtml(ip, null, null, { groupedIpCount: 2 })

    expect(html).toContain('title="Diese Zeile fasst 2 Quell-IPs')
    expect(html).toContain('class="badge spf" title="Die Quell-IP liegt')
    expect(html).toContain('title="Ermittelter Standort der IP: DE · Berlin."')
    expect(html).toContain('title="Autonomous System Number (ASN):')
    expect(html).toContain('title="Erkannter Versanddienst: Example Mail')
    expect(html).toContain('title="Cloud- oder Hosting-Netz')
    expect(html).toContain('title="Die IP ist auf der DNS-Blockliste')
    expect(html).toContain('title="Die IP ist auf der DNS-Allowlist')
    expect(html).toContain('title="Reverse-DNS-Hostname (PTR)')
  })

  it('uses only the supplied domain prefixes for a problem source SPF badge', () => {
    const ip = '203.0.113.10'
    const globalPrefix = parseCidr('global', '203.0.113.0/24')
    const otherPrefix = parseCidr('domain', '198.51.100.0/24')
    if (!globalPrefix || !otherPrefix) throw new Error('Expected valid test CIDRs')
    state.spfPrefixes = [globalPrefix]

    const html = formatIpMetaHtml(ip, null, null, {
      spfPrefixes: [otherPrefix],
      spfDomain: 'example.com'
    })

    expect(html).not.toContain('badge spf')
  })

  it('prefers a matching defined sending service over the detected provider', () => {
    const ip = '203.0.113.10'
    state.ipLabelCache.set(ip, {
      ip,
      ptr: null,
      provider: 'Netcup',
      senderKind: null,
      country: null,
      countryCode: null,
      city: null,
      lat: null,
      lon: null,
      asn: 64500,
      asOrg: 'Example Network',
      cloudProvider: null,
      dnsblHits: [],
      geoSource: 'none'
    } satisfies IpInfo)
    state.sendingServices = [
      {
        id: 'service-1',
        provider: 'Eigener Versanddienst',
        domain: 'example.test',
        cidr: '203.0.113.0/24',
        asn: null,
        status: 'known',
        note: null,
        team: null,
        createdAt: '2024-01-01T00:00:00.000Z',
        updatedAt: '2024-01-01T00:00:00.000Z'
      }
    ]

    const html = formatIpMetaHtml(ip, null, null, { sendingDomain: 'example.test' })

    expect(html).toContain('>Eigener Versanddienst</span>')
    expect(html).toContain('title="Als Sende-Dienst definiert: Eigener Versanddienst."')
    expect(html).not.toContain('>Example Network</span>')
  })
})
