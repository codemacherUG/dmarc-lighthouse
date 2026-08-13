import { describe, expect, it } from 'vitest'
import {
  evaluateTransportSecurity,
  mxMatchesPattern,
  parseMtaStsPolicy,
  parseMtaStsTxt,
  parseTlsRptRecord
} from '../src/shared/transport'
import { decodeTlsaAnswers, encodeName, encodeQuery, formatTlsa } from '../src/main/dnswire'
import type { DaneMxCheck, MtaStsCheck, TlsRptCheck } from '../src/shared/types'

function base(input: {
  tlsrpt?: Partial<TlsRptCheck>
  mtaSts?: Partial<MtaStsCheck>
  mx?: DaneMxCheck[]
}): Parameters<typeof evaluateTransportSecurity>[0] {
  return {
    domain: 'example.com',
    tlsrpt: { found: true, records: [], rua: ['mailto:tls@example.com'], ...input.tlsrpt },
    mtaSts: {
      found: true,
      id: '20260101T000000',
      records: [],
      policyUrl: 'https://mta-sts.example.com/.well-known/mta-sts.txt',
      policy: {
        version: 'STSv1',
        mode: 'enforce',
        mx: ['mail.example.com'],
        maxAgeSeconds: 604800
      },
      ...input.mtaSts
    },
    dane: {
      mx: input.mx ?? [
        { host: 'mail.example.com', preference: 10, tlsa: ['3 1 1 abcd'], found: true }
      ]
    },
    checkedAt: '2026-08-13T00:00:00.000Z'
  }
}

describe('parseTlsRptRecord', () => {
  it('reads the report targets', () => {
    expect(
      parseTlsRptRecord(['v=TLSRPTv1; rua=mailto:tls@example.com,https://tls.example.com/report'])
    ).toEqual({
      found: true,
      rua: ['mailto:tls@example.com', 'https://tls.example.com/report']
    })
  })

  it('ignores unrelated TXT records', () => {
    expect(parseTlsRptRecord(['v=spf1 -all'])).toEqual({ found: false, rua: [] })
  })
})

describe('parseMtaStsTxt', () => {
  it('reads the policy id', () => {
    expect(parseMtaStsTxt(['v=STSv1; id=20260813T120000;'])).toEqual({
      found: true,
      id: '20260813T120000'
    })
  })

  it('reports a missing record', () => {
    expect(parseMtaStsTxt([])).toEqual({ found: false, id: null })
  })
})

describe('parseMtaStsPolicy', () => {
  it('collects mode, max_age and every mx line', () => {
    const policy = parseMtaStsPolicy(
      [
        'version: STSv1',
        'mode: testing',
        'mx: mail.example.com',
        'mx: *.backup.example.',
        'max_age: 86400'
      ].join('\r\n')
    )
    expect(policy).toEqual({
      version: 'STSv1',
      mode: 'testing',
      mx: ['mail.example.com', '*.backup.example'],
      maxAgeSeconds: 86400
    })
  })

  it('leaves an unknown mode unset', () => {
    expect(parseMtaStsPolicy('mode: whatever').mode).toBeNull()
  })
})

describe('mxMatchesPattern', () => {
  it('matches exact hosts and single-label wildcards', () => {
    expect(mxMatchesPattern('mail.example.com', 'mail.example.com')).toBe(true)
    expect(mxMatchesPattern('mx1.example.com', '*.example.com')).toBe(true)
    expect(mxMatchesPattern('a.b.example.com', '*.example.com')).toBe(false)
    expect(mxMatchesPattern('example.com', '*.example.com')).toBe(false)
  })
})

function reasonKeys(out: { reasons: { key: string }[] }): string[] {
  return out.reasons.map((r) => r.key)
}

describe('evaluateTransportSecurity', () => {
  it('rates a complete setup as ok', () => {
    const out = evaluateTransportSecurity(base({}))
    expect(out.status).toBe('ok')
    expect(reasonKeys(out)).toContain('transport.reason.mtaStsEnforce')
    expect(reasonKeys(out)).toContain('transport.reason.daneAll')
  })

  it('warns about a missing TLS-RPT record', () => {
    const out = evaluateTransportSecurity(base({ tlsrpt: { found: false, rua: [] } }))
    expect(out.status).toBe('warn')
    expect(reasonKeys(out)).toContain('transport.reason.noTlsrpt')
  })

  it('treats an unreachable policy as critical', () => {
    const out = evaluateTransportSecurity(
      base({ mtaSts: { policy: null, policyError: 'HTTP 404' } })
    )
    expect(out.status).toBe('bad')
    expect(reasonKeys(out)).toContain('transport.reason.policyMissing')
  })

  it('is critical when enforce mode misses an MX host', () => {
    const out = evaluateTransportSecurity(
      base({
        mx: [
          { host: 'mail.example.com', preference: 10, tlsa: [], found: false },
          { host: 'backup.other.test', preference: 20, tlsa: [], found: false }
        ]
      })
    )
    expect(out.status).toBe('bad')
    expect(reasonKeys(out)).toContain('transport.reason.mxNotCovered')
  })

  it('only warns about an uncovered MX while testing', () => {
    const out = evaluateTransportSecurity(
      base({
        mtaSts: {
          policy: {
            version: 'STSv1',
            mode: 'testing',
            mx: ['mail.example.com'],
            maxAgeSeconds: 604800
          }
        },
        mx: [{ host: 'backup.other.test', preference: 20, tlsa: [], found: false }]
      })
    )
    expect(out.status).toBe('warn')
    expect(reasonKeys(out)).toContain('transport.reason.mxNotCovered')
  })

  it('warns about a short max_age and lists that finding first', () => {
    const out = evaluateTransportSecurity(
      base({
        mtaSts: {
          policy: {
            version: 'STSv1',
            mode: 'enforce',
            mx: ['mail.example.com'],
            maxAgeSeconds: 3600
          }
        }
      })
    )
    expect(out.status).toBe('warn')
    expect(out.reasons[0]).toEqual({ key: 'transport.reason.shortMaxAge', level: 'warn' })
  })

  it('does not penalise a domain without DANE', () => {
    const out = evaluateTransportSecurity(
      base({ mx: [{ host: 'mail.example.com', preference: 10, tlsa: [], found: false }] })
    )
    expect(out.status).toBe('ok')
    expect(reasonKeys(out)).toContain('transport.reason.noDane')
    expect(out.reasons.find((r) => r.key === 'transport.reason.noDane')?.level).toBe('ok')
  })
})

describe('DNS wire format', () => {
  it('encodes names as length-prefixed labels', () => {
    expect([...encodeName('_25._tcp.mail.example.com.')].slice(0, 4)).toEqual([3, 0x5f, 0x32, 0x35])
    expect([...encodeName('a.b')]).toEqual([1, 0x61, 1, 0x62, 0])
  })

  it('builds a TLSA query with EDNS0', () => {
    const query = encodeQuery('mail.example.com', 52, 0x1234)
    expect(query.readUInt16BE(0)).toBe(0x1234)
    expect(query.readUInt16BE(4)).toBe(1)
    expect(query.readUInt16BE(10)).toBe(1)
    // Question type TLSA and class IN sit right before the OPT record.
    const optStart = query.length - 11
    expect(query.readUInt16BE(optStart - 4)).toBe(52)
    expect(query.readUInt16BE(optStart - 2)).toBe(1)
    expect(query[optStart + 2]).toBe(41)
  })

  it('decodes TLSA answers behind a compressed name', () => {
    const question = Buffer.concat([encodeName('_25._tcp.mail.example.com'), Buffer.alloc(4)])
    question.writeUInt16BE(52, question.length - 4)
    question.writeUInt16BE(1, question.length - 2)
    const header = Buffer.alloc(12)
    header.writeUInt16BE(0x8180, 2)
    header.writeUInt16BE(1, 4)
    header.writeUInt16BE(1, 6)
    const rdata = Buffer.from([3, 1, 1, 0xaa, 0xbb, 0xcc])
    const answer = Buffer.alloc(12 + rdata.length)
    answer.writeUInt16BE(0xc00c, 0) // pointer to the question name
    answer.writeUInt16BE(52, 2)
    answer.writeUInt16BE(1, 4)
    answer.writeUInt32BE(3600, 6)
    answer.writeUInt16BE(rdata.length, 10)
    rdata.copy(answer, 12)

    const records = decodeTlsaAnswers(Buffer.concat([header, question, answer]))
    expect(records).toEqual([{ usage: 3, selector: 1, matchingType: 1, data: 'aabbcc' }])
    expect(formatTlsa(records[0])).toBe('3 1 1 aabbcc')
  })

  it('reports NXDOMAIN as no records', () => {
    const header = Buffer.alloc(12)
    header[3] = 3
    expect(decodeTlsaAnswers(header)).toEqual([])
  })
})
