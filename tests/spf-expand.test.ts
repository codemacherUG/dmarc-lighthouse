import { describe, expect, it } from 'vitest'
import { parseSpfTerms, spfIpMechanismToCidr } from '../src/main/spf-expand'

describe('spf-expand helpers', () => {
  it('parses SPF terms', () => {
    expect(
      parseSpfTerms('v=spf1 ip4:203.0.113.0/24 include:_spf.example.com -all')
    ).toEqual(['ip4:203.0.113.0/24', 'include:_spf.example.com', '-all'])
  })

  it('normalizes ip4/ip6 mechanisms to CIDRs', () => {
    expect(spfIpMechanismToCidr('ip4', '203.0.113.5')).toBe('203.0.113.5/32')
    expect(spfIpMechanismToCidr('ip4', '203.0.113.0/24')).toBe('203.0.113.0/24')
    expect(spfIpMechanismToCidr('ip6', '2001:db8::1')).toBe('2001:db8::1/128')
    expect(spfIpMechanismToCidr('ip6', '2001:db8::/32')).toBe('2001:db8::/32')
    expect(spfIpMechanismToCidr('ip4', 'not-an-ip')).toBeNull()
  })
})
