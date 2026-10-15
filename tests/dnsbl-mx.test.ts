import { beforeEach, describe, expect, it, vi } from 'vitest'

const resolverMocks = vi.hoisted(() => ({
  resolve4: vi.fn(),
  resolve6: vi.fn()
}))

vi.mock('../src/main/dns-env', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../src/main/dns-env')>()),
  configureDnsEnvironment: vi.fn(),
  resolve4Reliable: resolverMocks.resolve4,
  resolve6Reliable: resolverMocks.resolve6
}))

import { lookupMxDnsbl } from '../src/main/dnsbl'

describe('lookupMxDnsbl', () => {
  beforeEach(() => {
    resolverMocks.resolve4.mockReset()
    resolverMocks.resolve6
      .mockReset()
      .mockRejectedValue(Object.assign(new Error('No data'), { code: 'ENODATA' }))
  })

  it('checks each unique MX address and returns blacklist hits, not whitelist hits', async () => {
    resolverMocks.resolve4.mockImplementation(async (name: string) => {
      if (name === 'mx1.example.com' || name === 'mx2.example.com') return ['192.0.2.10']
      if (name.endsWith('.zen.spamhaus.org')) return ['127.0.0.2']
      if (name.endsWith('.list.dnswl.org')) return ['127.0.0.1']
      return []
    })

    await expect(
      lookupMxDnsbl([{ exchange: 'mx1.example.com' }, { exchange: 'mx2.example.com' }])
    ).resolves.toEqual([
      { exchange: 'mx1.example.com', addresses: [{ ip: '192.0.2.10', lists: ['spamhaus-zen'] }] },
      { exchange: 'mx2.example.com', addresses: [{ ip: '192.0.2.10', lists: ['spamhaus-zen'] }] }
    ])
    expect(resolverMocks.resolve4).toHaveBeenCalledTimes(4)
  })

  it('reports MX addresses that have no blacklist hits', async () => {
    resolverMocks.resolve4.mockImplementation(async (name: string) =>
      name === 'mx.example.com' ? ['192.0.2.20'] : []
    )

    await expect(lookupMxDnsbl([{ exchange: 'mx.example.com' }])).resolves.toEqual([
      { exchange: 'mx.example.com', addresses: [{ ip: '192.0.2.20', lists: [] }] }
    ])
  })
})
