import { describe, expect, it } from 'vitest'
import { expandSpf, parseSpfTerms, spfIpMechanismToCidr } from '../src/main/spf-expand'
import { isCidrSubnetOf } from '../src/shared/ipcidr'

describe('spf-expand helpers', () => {
  it('parses SPF terms', () => {
    expect(parseSpfTerms('v=spf1 ip4:203.0.113.0/24 include:_spf.example.com -all')).toEqual([
      'ip4:203.0.113.0/24',
      'include:_spf.example.com',
      '-all'
    ])
  })

  it('normalizes ip4/ip6 mechanisms to CIDRs', () => {
    expect(spfIpMechanismToCidr('ip4', '203.0.113.5')).toBe('203.0.113.5/32')
    expect(spfIpMechanismToCidr('ip4', '203.0.113.0/24')).toBe('203.0.113.0/24')
    expect(spfIpMechanismToCidr('ip6', '2001:db8::1')).toBe('2001:db8::1/128')
    expect(spfIpMechanismToCidr('ip6', '2001:db8::/32')).toBe('2001:db8::/32')
    expect(spfIpMechanismToCidr('ip4', 'not-an-ip')).toBeNull()
  })

  it('checks whether one CIDR is a subnet of another', () => {
    expect(isCidrSubnetOf('203.0.113.5/32', '203.0.113.0/24')).toBe(true)
    expect(isCidrSubnetOf('203.0.113.0/24', '203.0.113.5/32')).toBe(false)
    expect(isCidrSubnetOf('2001:db8:0:1::1/128', '2001:db8::/32')).toBe(true)
    expect(isCidrSubnetOf('2001:db9::1/128', '2001:db8::/32')).toBe(false)
  })

  it('builds a lookup tree with RFC 7208 lookup counts and optimizer hints', async () => {
    const txtMap: Record<string, string[]> = {
      '_spf.provider.example': [
        'v=spf1 include:_netblocks.provider.example ip4:198.51.100.0/24 -all'
      ],
      '_netblocks.provider.example': ['v=spf1 ip4:203.0.113.0/24 -all']
    }

    const result = await expandSpf('example.com', {
      record:
        'v=spf1 include:_spf.provider.example include:_netblocks.provider.example ip4:198.51.100.10 ip4:192.0.2.0/24 ip4:192.0.2.5 a mx ~all',
      resolvers: {
        resolveTxt: async (host) => (txtMap[host] ? txtMap[host].map((r) => [r]) : []),
        resolve4: async () => [],
        resolve6: async () => [],
        resolveMx: async () => [{ exchange: 'mx1.example.com', priority: 10 }]
      }
    })

    // Root evaluation = 0 lookups;
    // include:_spf.provider.example = 1 + nested include:_netblocks.provider.example = 1 (total 2);
    // second include:_netblocks.provider.example = 1 (duplicate);
    // a = 1; mx = 1 => total 5 DNS lookups
    expect(result.lookups).toBe(5)
    expect(result.tree?.ownLookups).toBe(0)
    expect(result.tree?.totalLookups).toBe(5)

    const firstInclude = result.tree?.children.find(
      (c) => c.term === 'include:_spf.provider.example'
    )
    expect(firstInclude?.ownLookups).toBe(1)
    expect(firstInclude?.totalLookups).toBe(2)

    const duplicateInclude = result.tree?.children.find(
      (c) => c.term === 'include:_netblocks.provider.example'
    )
    expect(duplicateInclude?.duplicate).toBe(true)
    expect(duplicateInclude?.ownLookups).toBe(1)

    const hintCodes = (result.hints ?? []).map((h) => h.code)
    expect(hintCodes).toContain('duplicate-include')
    expect(hintCodes).toContain('redundant-cidr')
    expect(hintCodes).toContain('covered-by-include')
    expect(hintCodes).toContain('empty-mechanism')
    expect(hintCodes).toContain('all-softfail')
  })
})
