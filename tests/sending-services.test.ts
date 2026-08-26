import { mkdtempSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { afterEach, describe, expect, it } from 'vitest'
import {
  alertableSendingSources,
  groupNewSendingSources,
  matchSendingService,
  parseDomainList
} from '../src/shared/sending-services'
import type { ReportRow, SendingService } from '../src/shared/types'
import {
  deleteSendingService,
  listSendingServices,
  loadCachedReports,
  saveCache,
  setCacheUserDataForTests,
  upsertIpEnrichment,
  upsertSendingService
} from '../src/main/cache'

function service(overrides: Partial<SendingService> = {}): SendingService {
  return {
    id: 'svc1',
    provider: 'Microsoft 365',
    domain: 'example.de',
    cidr: null,
    asn: null,
    status: 'known',
    note: null,
    team: null,
    createdAt: '2024-01-01T00:00:00.000Z',
    updatedAt: '2024-01-01T00:00:00.000Z',
    ...overrides
  }
}

describe('matchSendingService', () => {
  it('returns null when the provider is unrecognized and no entry scopes by network', () => {
    expect(
      matchSendingService([service()], { provider: null, domain: 'example.de', ip: '1.2.3.4' })
    ).toBeNull()
  })

  it('matches an unrecognized sender via a CIDR-scoped entry (no provider name needed)', () => {
    const svc = service({ provider: 'Unbekannt (bestätigt)', cidr: '203.0.113.0/24' })
    expect(
      matchSendingService([svc], { provider: null, domain: 'example.de', ip: '203.0.113.77' })?.id
    ).toBe('svc1')
    expect(
      matchSendingService([svc], { provider: null, domain: 'example.de', ip: '198.51.100.1' })
    ).toBeNull()
  })

  it('matches an unrecognized sender via an ASN-scoped entry', () => {
    const svc = service({ provider: 'Unbekannt (bestätigt)', cidr: null, asn: 64500 })
    expect(
      matchSendingService([svc], {
        provider: null,
        domain: 'example.de',
        ip: '1.1.1.1',
        asn: 64500
      })?.id
    ).toBe('svc1')
    expect(
      matchSendingService([svc], {
        provider: null,
        domain: 'example.de',
        ip: '1.1.1.1',
        asn: 64501
      })
    ).toBeNull()
  })

  it('matches on provider + domain', () => {
    const svc = service()
    const match = matchSendingService([svc], {
      provider: 'Microsoft 365',
      domain: 'example.de',
      ip: '40.92.0.1'
    })
    expect(match?.id).toBe('svc1')
  })

  it('does not match a different domain when the entry is domain-scoped', () => {
    const svc = service({ domain: 'example.de' })
    const match = matchSendingService([svc], {
      provider: 'Microsoft 365',
      domain: 'other.de',
      ip: '40.92.0.1'
    })
    expect(match).toBeNull()
  })

  it('matches every domain when the entry has no domain scope', () => {
    const svc = service({ domain: null })
    const match = matchSendingService([svc], {
      provider: 'Microsoft 365',
      domain: 'anything.de',
      ip: '40.92.0.1'
    })
    expect(match?.id).toBe('svc1')
  })

  it('matches any domain listed in a comma-separated domain scope', () => {
    const svc = service({ domain: 'example.de, example.com,\nexample.net' })
    for (const domain of ['example.de', 'example.com', 'example.net']) {
      expect(
        matchSendingService([svc], { provider: 'Microsoft 365', domain, ip: '1.1.1.1' })?.id
      ).toBe('svc1')
    }
    expect(
      matchSendingService([svc], { provider: 'Microsoft 365', domain: 'other.de', ip: '1.1.1.1' })
    ).toBeNull()
  })

  it('requires the IP to fall inside a CIDR scope', () => {
    const svc = service({ cidr: '40.92.0.0/16' })
    expect(
      matchSendingService([svc], {
        provider: 'Microsoft 365',
        domain: 'example.de',
        ip: '40.92.5.5'
      })?.id
    ).toBe('svc1')
    expect(
      matchSendingService([svc], { provider: 'Microsoft 365', domain: 'example.de', ip: '9.9.9.9' })
    ).toBeNull()
  })

  it('matches any selected IP in a comma/newline-separated CIDR scope', () => {
    const svc = service({ cidr: '203.0.113.10/32,\n203.0.113.20/32' })
    for (const ip of ['203.0.113.10', '203.0.113.20']) {
      expect(
        matchSendingService([svc], { provider: 'Microsoft 365', domain: 'example.de', ip })?.id
      ).toBe('svc1')
    }
    expect(
      matchSendingService([svc], {
        provider: 'Microsoft 365',
        domain: 'example.de',
        ip: '203.0.113.30'
      })
    ).toBeNull()
  })

  it('requires a matching ASN scope', () => {
    const svc = service({ asn: 8075 })
    expect(
      matchSendingService([svc], {
        provider: 'Microsoft 365',
        domain: 'example.de',
        ip: '1.1.1.1',
        asn: 8075
      })?.id
    ).toBe('svc1')
    expect(
      matchSendingService([svc], {
        provider: 'Microsoft 365',
        domain: 'example.de',
        ip: '1.1.1.1',
        asn: 12345
      })
    ).toBeNull()
  })

  it('prefers the most specific entry when several match', () => {
    const generic = service({ id: 'generic', domain: null })
    const specific = service({ id: 'specific', domain: 'example.de' })
    const match = matchSendingService([generic, specific], {
      provider: 'Microsoft 365',
      domain: 'example.de',
      ip: '1.1.1.1'
    })
    expect(match?.id).toBe('specific')
  })
})

describe('parseDomainList', () => {
  it('splits on commas and newlines, trims, lowercases, and drops empties', () => {
    expect(parseDomainList('Example.DE, example.com,\n\nexample.net,')).toEqual([
      'example.de',
      'example.com',
      'example.net'
    ])
    expect(parseDomainList(null)).toEqual([])
    expect(parseDomainList('')).toEqual([])
  })
})

describe('groupNewSendingSources / alertableSendingSources', () => {
  it('groups new IPs by provider + domain and resolves inventory status', () => {
    const services = [service({ status: 'known' })]
    const groups = groupNewSendingSources(
      [
        { ip: '40.92.0.1', provider: 'Microsoft 365', domain: 'example.de' },
        { ip: '40.92.0.2', provider: 'Microsoft 365', domain: 'example.de' },
        { ip: '5.5.5.5', provider: null, domain: 'example.de' }
      ],
      services
    )
    expect(groups).toHaveLength(2)
    const known = groups.find((g) => g.provider === 'Microsoft 365')
    expect(known?.status).toBe('known')
    expect(known?.ips.sort()).toEqual(['40.92.0.1', '40.92.0.2'])
    const unknown = groups.find((g) => g.provider === null)
    expect(unknown?.status).toBe('unknown')
  })

  it('carries a single shared ASN through but clears it when the group mixes ASNs', () => {
    const uniform = groupNewSendingSources(
      [
        { ip: '1.1.1.1', provider: null, domain: 'example.de', asn: 64500 },
        { ip: '1.1.1.2', provider: null, domain: 'example.de', asn: 64500 }
      ],
      []
    )
    expect(uniform[0]?.asn).toBe(64500)

    const mixed = groupNewSendingSources(
      [
        { ip: '1.1.1.1', provider: null, domain: 'example.de', asn: 64500 },
        { ip: '1.1.1.2', provider: null, domain: 'example.de', asn: 64501 }
      ],
      []
    )
    expect(mixed[0]?.asn).toBeNull()
  })

  it('filters out groups already marked known, keeping retired/investigate/unknown', () => {
    const groups = groupNewSendingSources(
      [
        { ip: '1.1.1.1', provider: 'Microsoft 365', domain: 'example.de' },
        { ip: '2.2.2.2', provider: 'Old ESP', domain: 'example.de' },
        { ip: '3.3.3.3', provider: 'SendGrid', domain: 'example.de' },
        { ip: '4.4.4.4', provider: 'Review ESP', domain: 'example.de' }
      ],
      [
        service({ provider: 'Microsoft 365', status: 'known' }),
        service({ provider: 'Old ESP', status: 'retired', domain: 'example.de' }),
        service({ provider: 'Review ESP', status: 'investigate', domain: 'example.de' })
      ]
    )
    const alertable = alertableSendingSources(groups)
    expect(alertable.map((g) => g.provider).sort()).toEqual(['Old ESP', 'Review ESP', 'SendGrid'])
  })

  it('filters out acknowledged groups without remaining IPs', () => {
    const groups = groupNewSendingSources(
      [{ ip: '1.1.1.1', provider: null, domain: 'example.de' }],
      []
    )
    groups[0]!.ips = []
    expect(alertableSendingSources(groups)).toEqual([])
  })

  it('keeps known and unknown IPs in separate groups for the same provider and domain', () => {
    const groups = groupNewSendingSources(
      [
        { ip: '203.0.113.10', provider: null, domain: 'example.de' },
        { ip: '203.0.113.20', provider: null, domain: 'example.de' }
      ],
      [
        service({
          provider: 'Selected sender',
          cidr: '203.0.113.10/32',
          status: 'known'
        })
      ]
    )

    expect(groups).toHaveLength(2)
    expect(alertableSendingSources(groups)).toEqual([
      {
        provider: null,
        domain: 'example.de',
        ips: ['203.0.113.20'],
        status: 'unknown',
        asn: null
      }
    ])
  })
})

describe('sending-service persistence', () => {
  let dir: string

  afterEach(() => {
    setCacheUserDataForTests(null)
    if (dir) rmSync(dir, { recursive: true, force: true })
  })

  it('creates, lists, updates, and deletes entries', () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-sending-services-'))
    setCacheUserDataForTests(dir)

    const created = upsertSendingService({
      provider: 'Microsoft 365',
      domain: 'example.de',
      cidr: null,
      asn: null,
      status: 'unknown',
      note: null,
      team: null
    })
    expect(created.id).toBeTruthy()
    expect(listSendingServices()).toHaveLength(1)

    const updated = upsertSendingService({
      id: created.id,
      provider: 'Microsoft Exchange Online',
      domain: 'example.de, example.com',
      cidr: '40.92.0.0/16',
      asn: 8075,
      status: 'known',
      note: 'Sanctioned in 2024',
      team: 'IT Security'
    })
    expect(updated.id).toBe(created.id)
    expect(updated.createdAt).toBe(created.createdAt)
    const list = listSendingServices()
    expect(list).toHaveLength(1)
    expect(list[0]?.provider).toBe('Microsoft Exchange Online')
    expect(list[0]?.domain).toBe('example.de, example.com')
    expect(list[0]?.cidr).toBe('40.92.0.0/16')
    expect(list[0]?.asn).toBe(8075)
    expect(list[0]?.status).toBe('known')
    expect(list[0]?.team).toBe('IT Security')

    deleteSendingService(created.id)
    expect(listSendingServices()).toHaveLength(0)
  })

  it('reopens historical CIDR-matched sources when an inventory entry is deleted', () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-sending-services-'))
    setCacheUserDataForTests(dir)
    const accountKey = 'netcup-account'
    const ip = '159.195.74.209'
    const report: ReportRow = {
      reportId: 'netcup-report',
      orgName: 'receiver.example',
      domain: 'codemacher.de',
      dateBegin: '2026-08-24T00:00:00.000Z',
      dateEnd: '2026-08-25T00:00:00.000Z',
      total: 1,
      passing: 1,
      failing: 0,
      passRate: 100,
      policyP: 'reject',
      records: [
        {
          sourceIp: ip,
          count: 1,
          disposition: 'none',
          dkimResult: 'pass',
          spfResult: 'pass',
          headerFrom: 'codemacher.de',
          dkimDomain: 'codemacher.de',
          spfDomain: 'codemacher.de',
          dkimSelectors: ['default'],
          passesDmarc: true,
          reasons: []
        }
      ]
    }
    saveCache({
      accountKey,
      reports: [report],
      lastUid: 1,
      lastFailingTotal: 0,
      knownSourceIps: [ip]
    })
    upsertIpEnrichment([
      {
        ip,
        ptr: 'mail.netcup.example',
        provider: null,
        senderKind: null,
        country: null,
        countryCode: null,
        city: null,
        lat: null,
        lon: null,
        asn: 197540,
        asOrg: 'netcup GmbH',
        cloudProvider: null,
        dnsblHits: [],
        geoSource: 'none'
      }
    ])
    const created = upsertSendingService({
      provider: 'Netcup Server',
      domain: 'codemacher.de',
      cidr: `${ip}/32`,
      asn: null,
      status: 'known',
      note: null,
      team: null
    })

    expect(loadCachedReports(accountKey).meta.pendingSourceIps).toEqual([])
    expect(deleteSendingService(created.id)).toBe(1)
    expect(loadCachedReports(accountKey).meta.pendingSourceIps).toEqual([ip])
  })

  it('reopens sources excluded by an edited known-service scope', () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-sending-services-'))
    setCacheUserDataForTests(dir)
    const accountKey = 'edited-service-account'
    const oldIp = '203.0.113.10'
    const report: ReportRow = {
      reportId: 'edited-service-report',
      orgName: 'receiver.example',
      domain: 'example.de',
      dateBegin: '2026-08-24T00:00:00.000Z',
      dateEnd: '2026-08-25T00:00:00.000Z',
      total: 1,
      passing: 1,
      failing: 0,
      passRate: 100,
      policyP: 'reject',
      records: [
        {
          sourceIp: oldIp,
          count: 1,
          disposition: 'none',
          dkimResult: 'pass',
          spfResult: 'pass',
          headerFrom: 'example.de',
          dkimDomain: 'example.de',
          spfDomain: 'example.de',
          dkimSelectors: ['default'],
          passesDmarc: true,
          reasons: []
        }
      ]
    }
    saveCache({
      accountKey,
      reports: [report],
      lastUid: 1,
      lastFailingTotal: 0,
      knownSourceIps: [oldIp]
    })
    const created = upsertSendingService({
      provider: 'Example sender',
      domain: 'example.de',
      cidr: '203.0.113.0/24',
      asn: null,
      status: 'known',
      note: null,
      team: null
    })

    upsertSendingService({
      ...created,
      cidr: '198.51.100.0/24'
    })

    expect(loadCachedReports(accountKey).meta.pendingSourceIps).toEqual([oldIp])
  })

  it('does not reopen dismissed sources when deleting a non-known entry', () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-sending-services-'))
    setCacheUserDataForTests(dir)
    const accountKey = 'investigate-account'
    const ip = '203.0.113.10'
    saveCache({
      accountKey,
      reports: [
        {
          reportId: 'investigate-report',
          orgName: 'receiver.example',
          domain: 'example.de',
          dateBegin: '2026-08-24T00:00:00.000Z',
          dateEnd: '2026-08-25T00:00:00.000Z',
          total: 1,
          passing: 1,
          failing: 0,
          passRate: 100,
          policyP: 'reject',
          records: [
            {
              sourceIp: ip,
              count: 1,
              disposition: 'none',
              dkimResult: 'pass',
              spfResult: 'pass',
              headerFrom: 'example.de',
              dkimDomain: 'example.de',
              spfDomain: 'example.de',
              dkimSelectors: ['default'],
              passesDmarc: true,
              reasons: []
            }
          ]
        }
      ],
      lastUid: 1,
      lastFailingTotal: 0,
      knownSourceIps: [ip]
    })
    const created = upsertSendingService({
      provider: 'Review sender',
      domain: 'example.de',
      cidr: `${ip}/32`,
      asn: null,
      status: 'investigate',
      note: null,
      team: null
    })

    expect(deleteSendingService(created.id)).toBe(0)
    expect(loadCachedReports(accountKey).meta.pendingSourceIps).toEqual([])
  })
})
