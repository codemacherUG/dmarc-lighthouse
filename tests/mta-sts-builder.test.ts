import { describe, expect, it } from 'vitest'
import {
  buildMtaStsPolicyFile,
  buildMtaStsRecord,
  generateMtaStsId,
  isMtaStsMxPattern,
  mtaStsPoliciesEquivalent,
  parseMtaStsBuilderPolicy,
  parseMtaStsBuilderTxt,
  validateMtaStsBuilderStep
} from '../src/shared/mta-sts-builder'

describe('mta-sts-builder', () => {
  it('builds TXT and policy file', () => {
    const result = buildMtaStsRecord(
      {
        domain: 'Example.COM.',
        mode: 'testing',
        mx: ['mail.example.com.', '*.backup.example.net'],
        maxAgeSeconds: 86400,
        id: '20260814T091200'
      },
      new Date('2026-08-14T09:12:00Z')
    )
    expect(result.dns.host).toBe('_mta-sts.example.com')
    expect(result.dns.type).toBe('TXT')
    expect(result.dns.value).toBe('v=STSv1; id=20260814T091200')
    expect(result.httpsHost).toBe('mta-sts.example.com')
    expect(result.policyUrl).toBe('https://mta-sts.example.com/.well-known/mta-sts.txt')
    expect(result.policyText).toBe(
      [
        'version: STSv1',
        'mode: testing',
        'mx: mail.example.com',
        'mx: *.backup.example.net',
        'max_age: 86400',
        ''
      ].join('\n')
    )
  })

  it('generates a timestamp id when none is given', () => {
    const id = generateMtaStsId(new Date('2026-08-14T09:12:03Z'))
    expect(id).toBe('20260814T091203')
    const result = buildMtaStsRecord(
      {
        domain: 'example.com',
        mode: 'enforce',
        mx: ['mail.example.com'],
        maxAgeSeconds: 604800,
        id: ''
      },
      new Date('2026-08-14T09:12:03Z')
    )
    expect(result.id).toBe('20260814T091203')
  })

  it('accepts exact hosts and one-label wildcards', () => {
    expect(isMtaStsMxPattern('mail.example.com')).toBe(true)
    expect(isMtaStsMxPattern('*.example.com')).toBe(true)
    expect(isMtaStsMxPattern('*.mail.example.com')).toBe(true)
    expect(isMtaStsMxPattern('localhost')).toBe(false)
    expect(isMtaStsMxPattern('*.')).toBe(false)
  })

  it('parses live TXT and policy into form fields', () => {
    expect(parseMtaStsBuilderTxt('v=STSv1; id=20260813T120000')).toEqual({
      id: '20260813T120000'
    })
    const parsed = parseMtaStsBuilderPolicy(
      ['version: STSv1', 'mode: enforce', 'mx: mail.example.com', 'max_age: 1209600'].join('\n')
    )
    expect(parsed.mode).toBe('enforce')
    expect(parsed.mx).toEqual(['mail.example.com'])
    expect(parsed.maxAgeSeconds).toBe(1209600)
  })

  it('compares policies without the id', () => {
    expect(
      mtaStsPoliciesEquivalent(
        { mode: 'testing', mx: ['b.example.com', 'a.example.com'], maxAgeSeconds: 86400 },
        { mode: 'testing', mx: ['a.example.com', 'b.example.com'], maxAgeSeconds: 86400 }
      )
    ).toBe(true)
    expect(
      mtaStsPoliciesEquivalent(
        { mode: 'testing', mx: ['mail.example.com'], maxAgeSeconds: 86400 },
        { mode: 'enforce', mx: ['mail.example.com'], maxAgeSeconds: 86400 }
      )
    ).toBe(false)
  })

  it('round-trips the policy file through the parser', () => {
    const text = buildMtaStsPolicyFile({
      domain: 'example.com',
      mode: 'enforce',
      mx: ['mail.example.com'],
      maxAgeSeconds: 604800,
      id: 'x'
    })
    expect(parseMtaStsBuilderPolicy(text)).toEqual({
      mode: 'enforce',
      mx: ['mail.example.com'],
      maxAgeSeconds: 604800
    })
  })

  it('validates wizard steps', () => {
    expect(
      validateMtaStsBuilderStep('domain', {
        domain: '',
        mode: 'testing',
        mx: [],
        maxAgeSeconds: 604800,
        id: ''
      })
    ).toBe('mtaStsBuilder.error.domain')

    expect(
      validateMtaStsBuilderStep('policy', {
        domain: 'example.com',
        mode: 'testing',
        mx: [],
        maxAgeSeconds: 604800,
        id: ''
      })
    ).toBe('mtaStsBuilder.error.mx')

    expect(
      validateMtaStsBuilderStep('policy', {
        domain: 'example.com',
        mode: 'testing',
        mx: ['not a host'],
        maxAgeSeconds: 604800,
        id: ''
      })
    ).toBe('mtaStsBuilder.error.mxPattern')

    expect(
      validateMtaStsBuilderStep('policy', {
        domain: 'example.com',
        mode: 'testing',
        mx: ['mail.example.com'],
        maxAgeSeconds: 0,
        id: ''
      })
    ).toBe('mtaStsBuilder.error.maxAge')

    expect(
      validateMtaStsBuilderStep('policy', {
        domain: 'example.com',
        mode: 'testing',
        mx: ['mail.example.com'],
        maxAgeSeconds: 86400,
        id: ''
      })
    ).toBeNull()
  })
})
