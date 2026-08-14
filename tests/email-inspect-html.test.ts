import { describe, expect, it } from 'vitest'
import { inspectEmail } from '../src/shared/email-inspect'
import {
  buildEmailInspectReportHtml,
  emailInspectPdfFilename
} from '../src/shared/email-inspect-html'

const SAMPLE = `Return-Path: <newsletter@example.com>
Received: from smtp.example.com (smtp.example.com [192.0.2.10])
        by mx.example.net with ESMTPS id xyz
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 13 Aug 2026 10:00:58 -0700
Authentication-Results: mx.example.net;
       dkim=pass header.i=@example.com header.s=selector1;
       spf=pass smtp.mailfrom=newsletter@example.com;
       dmarc=pass header.from=example.com
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1; b=def
From: Example News <newsletter@example.com>
To: User <user@example.com>
Subject: August Update
Date: Thu, 13 Aug 2026 17:00:00 +0000
Message-ID: <news@example.com>
MIME-Version: 1.0
Content-Type: text/plain

Hello
`

describe('emailInspectPdfFilename', () => {
  it('slugs the source name and keeps a pdf suffix', () => {
    expect(emailInspectPdfFilename('newsletter.eml')).toBe('email-inspect-newsletter.pdf')
    expect(emailInspectPdfFilename('My Mail.msg')).toBe('email-inspect-My_Mail.pdf')
  })
})

describe('buildEmailInspectReportHtml', () => {
  it('renders verdict, identity, checks and hops in German', () => {
    const result = inspectEmail(SAMPLE, 'newsletter.eml')
    const html = buildEmailInspectReportHtml({
      result,
      locale: 'de',
      appVersion: '1.0.23',
      generatedAt: '2026-08-14T09:00:00.000Z'
    })
    expect(html).toContain('E-Mail-Prüfung')
    expect(html).toContain('newsletter.eml')
    expect(html).toContain('newsletter@example.com')
    expect(html).toContain('Authentifizierung stimmt')
    expect(html).toContain('smtp.example.com')
    expect(html).toContain('TLS 1.3')
    expect(html).toContain('selector1._domainkey.example.com')
    expect(html).toContain('Nur Header ausgewertet')
    expect(html).not.toContain('Hello')
  })

  it('escapes untrusted header values', () => {
    const raw = `From: "x <script>alert(1)</script>" <safe@example.com>
To: user@example.com
Subject: <img src=x>
Date: Thu, 13 Aug 2026 17:00:00 +0000
MIME-Version: 1.0
Received: from smtp.example.com by mx.example.net; Thu, 13 Aug 2026 17:00:00 +0000
Authentication-Results: mx.example.net; spf=none; dkim=none; dmarc=none

body
`
    const html = buildEmailInspectReportHtml({
      result: inspectEmail(raw, 'xss.eml'),
      locale: 'en'
    })
    expect(html).not.toContain('<script>alert(1)</script>')
    expect(html).toContain('&lt;script&gt;')
    expect(html).toContain('&lt;img src=x&gt;')
  })
})
