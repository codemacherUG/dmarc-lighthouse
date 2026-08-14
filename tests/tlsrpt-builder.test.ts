import { describe, expect, it } from 'vitest'
import {
  buildTlsRptRecord,
  defaultTlsRptMailbox,
  normalizeTlsRptUri,
  parseTlsRptBuilderRecord,
  tlsrptRecordsEquivalent,
  validateTlsRptBuilderStep
} from '../src/shared/tlsrpt-builder'

describe('tlsrpt-builder', () => {
  it('suggests tlsrpt@domain', () => {
    expect(defaultTlsRptMailbox('Example.COM.')).toBe('tlsrpt@example.com')
  })

  it('builds a TXT record with mailto and https rua', () => {
    const result = buildTlsRptRecord({
      domain: 'Example.COM.',
      rua: 'tlsrpt@example.com, https://tls.example.com/report'
    })
    expect(result.host).toBe('_smtp._tls.example.com')
    expect(result.type).toBe('TXT')
    expect(result.value).toBe(
      'v=TLSRPTv1; rua=mailto:tlsrpt@example.com,https://tls.example.com/report'
    )
  })

  it('rejects http:// report URIs', () => {
    expect(normalizeTlsRptUri('http://tls.example.com/report')).toBeNull()
    expect(normalizeTlsRptUri('https://tls.example.com/report')).toBe(
      'https://tls.example.com/report'
    )
    expect(normalizeTlsRptUri('not-an-email')).toBeNull()
  })

  it('parses an existing record into form fields', () => {
    const parsed = parseTlsRptBuilderRecord(
      'v=TLSRPTv1; rua=mailto:a@example.com,https://tls.example.com/r'
    )
    expect(parsed.rua).toBe('a@example.com, https://tls.example.com/r')
  })

  it('treats rua order as equivalent', () => {
    expect(
      tlsrptRecordsEquivalent(
        'v=TLSRPTv1; rua=mailto:a@example.com,https://tls.example.com/r',
        'v=TLSRPTv1; rua=https://tls.example.com/r,mailto:a@example.com'
      )
    ).toBe(true)
  })

  it('validates wizard steps', () => {
    expect(validateTlsRptBuilderStep('domain', { domain: '', rua: '' })).toBe(
      'tlsrptBuilder.error.domain'
    )
    expect(validateTlsRptBuilderStep('reporting', { domain: 'example.com', rua: '' })).toBe(
      'tlsrptBuilder.error.rua'
    )
    expect(
      validateTlsRptBuilderStep('reporting', {
        domain: 'example.com',
        rua: 'http://bad.example.com'
      })
    ).toBe('tlsrptBuilder.error.ruaUri')
    expect(
      validateTlsRptBuilderStep('reporting', {
        domain: 'example.com',
        rua: 'tlsrpt@example.com'
      })
    ).toBeNull()
  })
})
