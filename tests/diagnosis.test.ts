import { describe, expect, it } from 'vitest'
import { diagnoseSource } from '../src/shared/diagnosis'
import { setLocale, t } from '../src/shared/i18n'
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

  it('records technical SPF and service signals without proving intent', () => {
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

  it('does not recommend adding SPF when the source network is already authorized', () => {
    const rec = record({
      spfDomain: 'tenant.outbound.protection.outlook.com',
      spfRawResult: 'fail',
      dkimDomain: 'tenant.onmicrosoft.com',
      dkimRawResult: 'fail'
    })

    const diag = diagnoseSource([rec], 'example.com', null, true)

    expect(diag?.action).toBe('checkDkimSigning')
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

  it('does not invent auth failures when an older cache entry lacks raw results', () => {
    const rec = record({
      spfDomain: 'tenant.outbound.protection.outlook.com',
      dkimDomain: 'tenant.onmicrosoft.com'
    })
    const diag = diagnoseSource(
      [rec],
      'example.com',
      { name: 'Microsoft 365', kind: 'mailbox' },
      true
    )

    expect(diag?.spf.raw).toBeNull()
    expect(diag?.dkim.raw).toBeNull()
    expect(diag?.action).toBe('reviewAuthResults')
  })

  it('keeps raw SPF results paired with their authentication domain', () => {
    const dominant = record({
      count: 8,
      spfDomain: 'dominant.example',
      spfRawResult: 'pass'
    })
    const other = record({
      count: 3,
      spfDomain: 'other.example',
      spfRawResult: 'fail'
    })

    const diag = diagnoseSource([dominant, other], 'example.com')

    expect(diag?.spf.domain).toBe('dominant.example')
    expect(diag?.spf.raw).toBe('pass')
  })

  it('marks receiver-flagged forwarding as not actionable', () => {
    const rec = record({ reasons: [{ type: 'forwarded', comment: null }] })
    const diag = diagnoseSource([rec], 'example.com')
    expect(diag?.category).toBe('forwarder')
    expect(diag?.verdict).toBe('forwarded')
    expect(diag?.action).toBe('reviewForwarder')
  })
})

describe('diagnosis wording', () => {
  it('does not infer organizational approval from SPF and service detection', () => {
    setLocale('de')

    expect(t('diagnosis.verdict.likelyLegit')).toBe('SPF-Netztreffer / Dienstzuordnung')
    expect(t('diagnosis.verdictHint.likelyLegit')).toContain('kein Beleg')
    expect(t('diagnosis.verdictHint.likelyLegit')).toContain('Mandant/Konto')
    expect(t('diagnosis.verdictHint.likelyLegit')).not.toContain('Versand ist gewollt')
    expect(t('diagnosis.action.checkDkimSigning', { domain: 'example.com' })).toContain(
      'Zuerst prüfen'
    )
    expect(t('diagnosis.spf.unknown', { domain: 'mx.example.com' })).toContain('nicht gespeichert')
  })

  it('provides the same qualification in English', () => {
    setLocale('en')

    expect(t('diagnosis.verdictHint.likelyLegit')).toContain('not proof')
    expect(t('diagnosis.action.checkDkimSigning', { domain: 'example.com' })).toContain(
      'First verify'
    )
    setLocale('de')
  })
})
