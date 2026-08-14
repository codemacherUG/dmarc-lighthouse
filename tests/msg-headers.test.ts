import { describe, expect, it } from 'vitest'
import { decodeEmailBytes, inspectEmail, EmailInspectError } from '../src/shared/email-inspect'
import { extractMsgRfc822 } from '../src/shared/msg-headers'
import { buildCompoundFile, utf16leZ } from './helpers/cfb-builder'

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
Content-Type: text/plain; charset=utf-8

Hello
`

describe('Outlook MSG headers', () => {
  it('extracts transport headers from a mini-stream MSG', () => {
    const msg = buildCompoundFile({
      '__substg1.0_007D001F': utf16leZ(SAMPLE)
    })
    const text = decodeEmailBytes(msg)
    expect(text).toContain('Authentication-Results:')
    const result = inspectEmail(text, 'ok.msg')
    expect(result.status).toBe('ok')
    expect(result.identity.from).toBe('newsletter@example.com')
    expect(result.hops.length).toBeGreaterThan(0)
  })

  it('extracts ANSI (001E) transport headers', () => {
    const ansi = new TextEncoder().encode(`${SAMPLE}\0`)
    const msg = buildCompoundFile({
      '__substg1.0_007D001E': ansi
    })
    expect(extractMsgRfc822(msg)).toContain('DKIM-Signature:')
  })

  it('reads large transport headers from regular FAT sectors', () => {
    const padding = 'X-Pad: ' + 'a'.repeat(4200)
    const large = `${SAMPLE}${padding}\n`
    const msg = buildCompoundFile({
      '__substg1.0_007D001F': utf16leZ(large)
    })
    const text = decodeEmailBytes(msg)
    expect(text).toContain('X-Pad:')
    expect(inspectEmail(text, 'large.msg').status).toBe('ok')
  })

  it('reconstructs identity headers when transport headers are missing', () => {
    const msg = buildCompoundFile({
      '__substg1.0_0037001F': utf16leZ('Hello'),
      '__substg1.0_5D02001F': utf16leZ('sender@example.com'),
      '__substg1.0_0042001F': utf16leZ('Example Sender'),
      '__substg1.0_0E04001F': utf16leZ('user@example.com'),
      '__substg1.0_1035001F': utf16leZ('<id@example.com>')
    })
    const result = inspectEmail(decodeEmailBytes(msg), 'noid.msg')
    expect(result.identity.from).toBe('sender@example.com')
    expect(result.identity.subject).toBe('Hello')
    expect(result.identity.to).toBe('user@example.com')
    expect(result.identity.messageId).toBe('<id@example.com>')
    expect(result.hops).toHaveLength(0)
    expect(result.status).not.toBe('ok')
  })

  it('rejects truncated OLE files', () => {
    const ole = Uint8Array.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])
    expect(() => decodeEmailBytes(ole)).toThrow(EmailInspectError)
    try {
      decodeEmailBytes(ole)
    } catch (err) {
      expect(err).toBeInstanceOf(EmailInspectError)
      expect((err as EmailInspectError).key).toBe('unsupportedMsg')
    }
  })
})
