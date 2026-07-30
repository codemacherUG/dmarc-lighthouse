import { describe, expect, it } from 'vitest'
import { parseForensicEmail, isLikelyForensicMime } from '../src/main/forensic'

const SAMPLE = `From: reporter@google.com
To: dmarc@example.com
Subject: DMARC Failure Report for example.com
MIME-Version: 1.0
Content-Type: multipart/report; report-type=feedback-report; boundary="b1"

--b1
Content-Type: text/plain; charset=utf-8

This is a DMARC aggregate failure report.

--b1
Content-Type: message/feedback-report

Feedback-Type: auth-failure
User-Agent: Google
Version: 1
Original-Mail-From: spoof@evil.example
Original-Rcpt-To: user@example.com
Arrival-Date: Thu, 30 Jul 2026 10:15:00 +0000
Source-IP: 203.0.113.50
Reported-Domain: example.com
Authentication-Results: mx.google.com; dmarc=fail
Delivery-Result: delivered
Auth-Failure: dmarc

--b1
Content-Type: text/rfc822-headers

From: Spoofed <spoof@evil.example>
To: user@example.com
Subject: Important invoice
Date: Thu, 30 Jul 2026 10:14:00 +0000

--b1--
`

describe('parseForensicEmail', () => {
  it('detects ARF forensic MIME', () => {
    expect(isLikelyForensicMime(SAMPLE)).toBe(true)
  })

  it('extracts sanitized failure fields', () => {
    const row = parseForensicEmail(SAMPLE)
    expect(row.reportedDomain).toBe('example.com')
    expect(row.sourceIp).toBe('203.0.113.50')
    expect(row.authFailure).toBe('dmarc')
    expect(row.envelopeFrom).toBe('spoof@evil.example')
    expect(row.headerFrom).toBe('spoof@evil.example')
    expect(row.feedbackType).toBe('auth-failure')
    expect(row.subject).toBe('Important invoice')
    expect(row.id).toHaveLength(24)
  })
})
