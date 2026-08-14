import { describe, expect, it } from 'vitest'
import { isLikelyMailboxIp } from '../src/shared/mailbox-ip'

describe('isLikelyMailboxIp', () => {
  it('matches well-known Google, Microsoft, Yahoo and iCloud blocks', () => {
    expect(isLikelyMailboxIp('66.249.64.1')).toBe(true)
    expect(isLikelyMailboxIp('2a00:1450:4864:20::346')).toBe(true)
    expect(isLikelyMailboxIp('40.92.0.10')).toBe(true)
    expect(isLikelyMailboxIp('104.47.0.1')).toBe(true)
    expect(isLikelyMailboxIp('74.6.0.1')).toBe(true)
    expect(isLikelyMailboxIp('17.57.10.1')).toBe(true)
    expect(isLikelyMailboxIp('2a01:111:f400::1')).toBe(true)
  })

  it('leaves unrelated and empty addresses alone', () => {
    expect(isLikelyMailboxIp('159.195.74.209')).toBe(false)
    expect(isLikelyMailboxIp('192.0.2.1')).toBe(false)
    expect(isLikelyMailboxIp('20.50.0.1')).toBe(false)
    expect(isLikelyMailboxIp('')).toBe(false)
  })
})
