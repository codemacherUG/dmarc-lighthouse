import { describe, expect, it } from 'vitest'
import { diagnoseSource } from '../src/shared/diagnosis'
import type { SerializedRecord } from '../src/shared/types'

function record(overrides: Partial<SerializedRecord> = {}): SerializedRecord {
  return {
    sourceIp: '192.0.2.1',
    count: 10,
    disposition: 'none',
    dkimResult: 'fail',
    spfResult: 'fail',
    headerFrom: 'example.com',
    dkimDomain: null,
    spfDomain: null,
    dkimSelectors: [],
    spfRawResult: null,
    dkimRawResult: null,
    passesDmarc: false,
    reasons: [],
    ...overrides
  }
}

describe('diagnoseSource', () => {
  it('returns null for an empty record set', () => {
    expect(diagnoseSource([], 'example.com')).toBeNull()
  })

  it('flags a foreign ESP with SPF pass unaligned and no DKIM as a signing gap', () => {
    const rec = record({
      spfDomain: 'outbound.protection.office365.com',
      spfRawResult: 'pass',
      dkimDomain: null
    })
    const diag = diagnoseSource(
      [rec],
      'example.com',
      { name: 'Microsoft 365', kind: 'mailbox' },
      true
    )
    expect(diag).not.toBeNull()
    expect(diag?.category).toBe('thirdParty')
    expect(diag?.verdict).toBe('likelyLegit')
    expect(diag?.action).toBe('checkDkimSigning')
    expect(diag?.spf.aligned).toBe(false)
    expect(diag?.spf.raw).toBe('pass')
    expect(diag?.senderName).toBe('Microsoft 365')
  })

  it('flags fully unauthenticated mail as suspicious when not an authorized sender', () => {
    const diag = diagnoseSource([record()], 'example.com')
    expect(diag?.category).toBe('unauthenticated')
    expect(diag?.verdict).toBe('suspicious')
    expect(diag?.action).toBe('investigateSpoof')
  })

  it('detects a broken own-domain DKIM signature (aligned but raw fail)', () => {
    const rec = record({
      dkimDomain: 'example.com',
      dkimRawResult: 'fail',
      spfDomain: null
    })
    const diag = diagnoseSource([rec], 'example.com', null, true)
    expect(diag?.category).toBe('broken')
    expect(diag?.dkim.aligned).toBe(true)
    expect(diag?.action).toBe('fixDkimAuth')
  })

  it('marks receiver-flagged forwarding as not actionable', () => {
    const rec = record({ reasons: [{ type: 'forwarded', comment: null }] })
    const diag = diagnoseSource([rec], 'example.com')
    expect(diag?.category).toBe('forwarder')
    expect(diag?.verdict).toBe('forwarded')
    expect(diag?.action).toBe('reviewForwarder')
  })
})
