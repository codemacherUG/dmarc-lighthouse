import { readFileSync } from 'node:fs'
import { gzipSync } from 'node:zlib'
import { describe, expect, it } from 'vitest'
import { parseLocalBuffers, parseMimeSources } from '../src/main/analyze'
import { parseTlsRptJson, parseTlsRptMime } from '../src/main/tlsrpt-report'

const report = {
  'organization-name': 'mx.example.net',
  'date-range': {
    'start-datetime': '2026-09-29T00:00:00Z',
    'end-datetime': '2026-09-30T00:00:00Z'
  },
  'report-id': 'tls-123',
  policies: [
    {
      policy: {
        'policy-type': 'sts',
        'policy-string': ['version: STSv1', 'mode: enforce'],
        'policy-domain': 'example.com',
        'mx-host': ['mail.example.com']
      },
      summary: {
        'total-successful-session-count': 17,
        'total-failure-session-count': 2
      },
      'failure-details': [
        {
          'result-type': 'validation-failure',
          'sending-mta-ip': '192.0.2.8',
          'receiving-mx-hostname': 'mail.example.com',
          'receiving-ip': '192.0.2.25',
          'failed-session-count': 2,
          'failure-reason-code': 'certificate-expired'
        }
      ]
    }
  ]
}

function mimeMessage(content: Buffer): Buffer {
  const encoded =
    content
      .toString('base64')
      .match(/.{1,76}/g)
      ?.join('\r\n') ?? ''
  return Buffer.from(
    [
      'From: reports@example.net',
      'To: tls@example.com',
      'Subject: Report domain: example.com; Submitter: mx.example.net; Report-ID: tls-123',
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary="tls-boundary"',
      '',
      '--tls-boundary',
      'Content-Type: application/tlsrpt+gzip',
      'Content-Disposition: attachment; filename="tls-report.json.gz"',
      'Content-Transfer-Encoding: base64',
      '',
      encoded,
      '--tls-boundary--',
      ''
    ].join('\r\n')
  )
}

describe('TLS-RPT report parsing', () => {
  it('normalizes counts, policies, and failure details from RFC JSON', () => {
    const parsed = parseTlsRptJson(JSON.stringify(report))
    expect(parsed).toMatchObject({
      reportId: 'tls-123',
      orgName: 'mx.example.net',
      successfulSessions: 17,
      failedSessions: 2,
      policies: [
        {
          policyType: 'sts',
          policyDomain: 'example.com',
          failureDetails: [{ resultType: 'validation-failure', failedSessionCount: 2 }]
        }
      ]
    })
  })

  it('extracts gzip JSON reports from a MIME attachment', async () => {
    const message = mimeMessage(gzipSync(Buffer.from(JSON.stringify(report))))
    await expect(parseTlsRptMime(message)).resolves.toMatchObject([
      { reportId: 'tls-123', failedSessions: 2 }
    ])
  })

  it('routes TLS-RPT mail into its own analysis result, not DMARC totals', async () => {
    const message = mimeMessage(gzipSync(Buffer.from(JSON.stringify(report))))
    const result = await parseMimeSources([{ uid: 1, source: message }])
    expect(result.tlsRptReports).toHaveLength(1)
    expect(result.aggregate.reportCount).toBe(0)
    expect(result.aggregate.total).toBe(0)
    expect(result.skipped).toBe(0)
  })

  it('imports standalone JSON and gzip JSON files', async () => {
    const json = Buffer.from(JSON.stringify(report))
    const result = await parseLocalBuffers([
      { name: 'tlsrpt-example.json', data: json },
      { name: 'tlsrpt-example.json.gz', data: gzipSync(json) }
    ])
    expect(result.tlsRptReports).toHaveLength(2)
    expect(result.newTlsRptReports).toBe(2)
    expect(result.skipped).toBe(0)
  })

  it('imports the bundled example report', async () => {
    const data = readFileSync(new URL('../docs/examples/tlsrpt-sample.json', import.meta.url))
    const result = await parseLocalBuffers([{ name: 'tlsrpt-sample.json', data }])
    expect(result.tlsRptReports).toMatchObject([
      { orgName: 'mx-reporting.example.net', successfulSessions: 247, failedSessions: 4 }
    ])
    expect(result.skipped).toBe(0)
  })

  it('does not classify unrelated JSON as a TLS-RPT report', () => {
    expect(parseTlsRptJson('{"message":"hello"}')).toBeNull()
  })
})
