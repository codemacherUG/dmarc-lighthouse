import { describe, expect, it } from 'vitest'
import { isRelaxedAligned, organizationalDomain } from '../src/shared/domain'
import { identifySender, identifySenderFromSpfInclude } from '../src/shared/sender'
import { categorizeFailure } from '../src/shared/analyze'
import type { SerializedRecord } from '../src/shared/types'

function record(overrides: Partial<SerializedRecord> = {}): SerializedRecord {
  return {
    sourceIp: '192.0.2.1',
    count: 1,
    disposition: 'none',
    dkimResult: 'fail',
    spfResult: 'fail',
    headerFrom: 'example.com',
    dkimDomain: null,
    spfDomain: null,
    dkimSelectors: [],
    passesDmarc: false,
    reasons: [],
    ...overrides
  }
}

describe('organizationalDomain', () => {
  it('keeps the registrable part of a subdomain', () => {
    expect(organizationalDomain('mail.example.com')).toBe('example.com')
    expect(organizationalDomain('a.b.c.example.com')).toBe('example.com')
  })

  it('handles multi-label public suffixes', () => {
    expect(organizationalDomain('shop.example.co.uk')).toBe('example.co.uk')
    expect(organizationalDomain('mail.example.com.au')).toBe('example.com.au')
  })

  it('normalises case and trailing dots', () => {
    expect(organizationalDomain('Mail.Example.COM.')).toBe('example.com')
  })

  it('returns null for empty input and keeps single-label hosts as-is', () => {
    expect(organizationalDomain('')).toBeNull()
    expect(organizationalDomain(null)).toBeNull()
    expect(organizationalDomain('localhost')).toBe('localhost')
  })

  it('uses the domain part of an address', () => {
    expect(organizationalDomain('bounce@mail.example.com')).toBe('example.com')
  })
})

describe('isRelaxedAligned', () => {
  it('aligns a subdomain with its organizational domain', () => {
    expect(isRelaxedAligned('mail.example.com', 'example.com')).toBe(true)
    expect(isRelaxedAligned('example.com', 'news.example.com')).toBe(true)
  })

  it('rejects unrelated domains', () => {
    expect(isRelaxedAligned('sendgrid.net', 'example.com')).toBe(false)
    expect(isRelaxedAligned(null, 'example.com')).toBe(false)
  })
})

describe('identifySender', () => {
  it('prefers the product over the network it runs on', () => {
    expect(
      identifySender({ ptr: 'o1.email-smtp.us-east-1.amazonses.com', asOrg: 'Amazon.com' })
    ).toEqual({ name: 'Amazon SES', kind: 'esp' })
    expect(identifySender({ ptr: 'mail-1.sendgrid.net', asOrg: 'Amazon.com, Inc.' })).toEqual({
      name: 'SendGrid',
      kind: 'esp'
    })
  })

  it('matches Microsoft 365 protection hosts', () => {
    expect(identifySender({ ptr: 'mail-am6eur05on2115.outbound.protection.outlook.com' })).toEqual({
      name: 'Microsoft 365',
      kind: 'mailbox'
    })
  })

  it('falls back to the AS organization', () => {
    expect(identifySender({ ptr: null, asOrg: 'Hetzner Online GmbH' })).toEqual({
      name: 'Hetzner',
      kind: 'infra'
    })
  })

  it('returns null for unknown senders', () => {
    expect(
      identifySender({ ptr: 'mail.some-company.example', asOrg: 'Some Company Ltd' })
    ).toBeNull()
  })

  it('identifies services from SPF include tokens', () => {
    expect(identifySenderFromSpfInclude('servers.mcsv.net')).toEqual({
      name: 'Mailchimp',
      kind: 'esp'
    })
  })
})

describe('categorizeFailure', () => {
  it('detects forwarding from the report reasons', () => {
    const rec = record({ reasons: [{ type: 'forwarded', comment: null }] })
    expect(categorizeFailure(rec, 'example.com')).toBe('forwarder')
  })

  it('flags records without any authenticated domain', () => {
    expect(categorizeFailure(record())).toBe('unauthenticated')
  })

  it('flags a third party signing under its own domain', () => {
    const rec = record({ dkimDomain: 'sendgrid.net', spfDomain: 'sendgrid.net' })
    expect(categorizeFailure(rec)).toBe('thirdParty')
  })

  it('treats an authenticated own domain as a configuration problem', () => {
    const rec = record({ dkimDomain: 'mail.example.com', spfDomain: 'bounces.other.net' })
    expect(categorizeFailure(rec)).toBe('broken')
  })

  it('falls back to the policy domain when header-from is missing', () => {
    const rec = record({ headerFrom: null, spfDomain: 'mail.example.com' })
    expect(categorizeFailure(rec, 'example.com')).toBe('broken')
  })
})
