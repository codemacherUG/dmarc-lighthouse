import { describe, expect, it } from 'vitest'
import { t, type MessageKey } from '../src/shared/i18n'
import {
  decodeEmailBytes,
  decodeEncodedWords,
  inspectEmail,
  looksLikeEmailMessage,
  normalizeTlsVersion,
  parseAuthResults,
  parseReceivedHop,
  EmailInspectError
} from '../src/shared/email-inspect'

const GMAIL = `Return-Path: <newsletter@example.com>
Received: from mail-yw1-f177.google.com (mail-yw1-f177.google.com. [192.0.2.177])
        by mx.google.com with ESMTPS id abc123
        for <user@example.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 Aug 2026 10:01:00 -0700
Received: from smtp.example.com (smtp.example.com [192.0.2.10])
        by mx.google.com with ESMTPS id xyz
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 13 Aug 2026 10:00:58 -0700
Authentication-Results: mx.google.com;
       dkim=pass header.i=@example.com header.s=selector1 header.b=abcd;
       spf=pass (google.com: domain of newsletter@example.com designates 192.0.2.10 as permitted sender) smtp.mailfrom=newsletter@example.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com
Received-SPF: pass (google.com: domain of newsletter@example.com designates 192.0.2.10 as permitted sender) client-ip=192.0.2.10;
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1; c=relaxed/relaxed;
        h=from:to:subject:date:message-id; bh=abc; b=def
From: Example News <newsletter@example.com>
To: User <user@example.com>
Subject: =?UTF-8?Q?August_Update?=
Date: Thu, 13 Aug 2026 17:00:00 +0000
Message-ID: <news@example.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Hello
`

const SPOOF = `Return-Path: <attacker@evil.example>
Received: from unknown (unknown [203.0.113.50])
        by mx.example.net (Postfix) with SMTP id 1
        for <user@example.com>; Thu, 13 Aug 2026 12:00:00 +0200
Authentication-Results: mx.example.net;
       spf=fail smtp.mailfrom=attacker@evil.example;
       dkim=none;
       dmarc=fail (p=reject dis=reject) header.from=example.com
From: "IT Support <it@example.com>" <attacker@evil.example>
Reply-To: it@example.com
To: user@example.com
Subject: Invoice
Date: Thu, 13 Aug 2026 12:00:00 +0200
MIME-Version: 1.0
Content-Type: text/plain

Pay now
`

const FORWARDED = `Return-Path: <forwarder@list.example>
Received: from lists.example.net (lists.example.net [198.51.100.8])
        by mx.google.com with ESMTPS
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256);
        Thu, 13 Aug 2026 11:00:00 +0000
Authentication-Results: mx.google.com;
       dkim=pass header.i=@example.com header.s=selector1;
       spf=fail smtp.mailfrom=forwarder@list.example;
       dmarc=pass header.from=example.com;
       arc=pass
ARC-Seal: i=1; a=rsa-sha256; cv=pass; d=google.com; s=arc
ARC-Authentication-Results: i=1; mx.google.com; spf=fail; dkim=pass; dmarc=pass
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1; b=abc
From: Sender <person@example.com>
To: user@example.com
Subject: List copy
Date: Thu, 13 Aug 2026 11:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain

Hi
`

describe('decodeEncodedWords', () => {
  it('decodes Q-encoded UTF-8 words', () => {
    expect(decodeEncodedWords('=?UTF-8?Q?August_Update?=')).toBe('August Update')
  })

  it('joins adjacent encoded words', () => {
    expect(decodeEncodedWords('=?utf-8?Q?Hello?= =?utf-8?Q?_World?=')).toBe('Hello World')
  })
})

describe('parseReceivedHop', () => {
  it('reads Postfix TLS and the source IP', () => {
    const hop = parseReceivedHop(
      'from smtp.example.com (smtp.example.com [192.0.2.10]) (using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256)) by mx.example.net (Postfix) with ESMTPS id ABC for <user@example.com>; Thu, 13 Aug 2026 12:00:00 +0200 (CEST)'
    )
    expect(hop.fromHost).toBe('smtp.example.com')
    expect(hop.fromIp).toBe('192.0.2.10')
    expect(hop.byHost).toBe('mx.example.net')
    expect(hop.protocol).toBe('ESMTPS')
    expect(hop.tlsVersion).toBe('TLS 1.3')
    expect(hop.tlsCipher).toBe('TLS_AES_256_GCM_SHA384')
    expect(hop.withTls).toBe(true)
    expect(hop.forAddr).toBe('user@example.com')
  })

  it('treats ESMTP without TLS as cleartext', () => {
    const hop = parseReceivedHop(
      'from unknown (unknown [203.0.113.50]) by mx.example.net with SMTP id 1; Thu, 13 Aug 2026 12:00:00 +0200'
    )
    expect(hop.withTls).toBe(false)
    expect(hop.tlsVersion).toBeNull()
    expect(hop.protocol).toBe('SMTP')
  })

  it('treats ESMTPS as TLS even without a version string', () => {
    const hop = parseReceivedHop(
      'from mail.example.com (mail.example.com [192.0.2.10]) by mx.example.net with ESMTPS id ABC; Thu, 13 Aug 2026 12:00:00 +0200'
    )
    expect(hop.protocol).toBe('ESMTPS')
    expect(hop.tlsVersion).toBeNull()
    expect(hop.withTls).toBe(true)
  })
})

describe('parseAuthResults', () => {
  it('reads Gmail-style methods and properties', () => {
    const block = parseAuthResults(
      'mx.google.com; dkim=pass header.i=@example.com header.s=selector1; spf=pass smtp.mailfrom=newsletter@example.com; dmarc=pass (p=REJECT) header.from=example.com'
    )
    expect(block.authservId).toBe('mx.google.com')
    expect(block.methods.map((m) => m.method)).toEqual(['dkim', 'spf', 'dmarc'])
    expect(block.methods[0].properties['header.i']).toBe('@example.com')
    expect(block.methods[1].properties['smtp.mailfrom']).toBe('newsletter@example.com')
  })

  it('accepts a missing authserv-id', () => {
    const block = parseAuthResults(
      'spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com'
    )
    expect(block.authservId).toBe('')
    expect(block.methods).toHaveLength(2)
  })

  it('treats a bare none as skipped checks', () => {
    const block = parseAuthResults('mail.example.com;\n\tnone')
    expect(block.authservId).toBe('mail.example.com')
    expect(block.methods).toHaveLength(0)
    expect(block.skipped).toBe(true)
  })
})

describe('normalizeTlsVersion', () => {
  it('normalizes common spellings', () => {
    expect(normalizeTlsVersion('TLS1_3')).toBe('TLS 1.3')
    expect(normalizeTlsVersion('TLSv1.2')).toBe('TLS 1.2')
    expect(normalizeTlsVersion('TLS1_0')).toBe('TLS 1.0')
  })
})

describe('inspectEmail', () => {
  it('grades a fully authenticated Gmail-style message as ok', () => {
    const result = inspectEmail(GMAIL, 'ok.eml')
    expect(result.identity.from).toBe('newsletter@example.com')
    expect(result.identity.fromDomain).toBe('example.com')
    expect(result.identity.subject).toBe('August Update')
    expect(result.hops).toHaveLength(2)
    expect(result.hops[0].index).toBe(1)
    expect(result.hops[0].fromIp).toBe('192.0.2.10')
    expect(result.hops.every((h) => h.withTls)).toBe(true)
    expect(result.status).toBe('ok')
    expect(result.verdictKey).toBe('email.verdict.ok')
    expect(result.checks.find((c) => c.id === 'spf')?.status).toBe('ok')
    expect(result.checks.find((c) => c.id === 'dkim')?.status).toBe('ok')
    expect(result.checks.find((c) => c.id === 'dmarc')?.status).toBe('ok')
    expect(result.checks.find((c) => c.id === 'tls')?.status).toBe('ok')
  })

  it('flags spoofing, DMARC fail, missing TLS and a display-name trick', () => {
    const result = inspectEmail(SPOOF, 'spoof.eml')
    expect(result.status).toBe('bad')
    expect(result.verdictKey).toBe('email.verdict.bad')
    expect(result.checks.find((c) => c.id === 'dmarc')?.status).toBe('bad')
    expect(result.checks.find((c) => c.id === 'spf')?.status).toBe('bad')
    expect(result.checks.find((c) => c.id === 'tls')?.status).toBe('warn')
    expect(result.checks.find((c) => c.id === 'displayName')?.status).toBe('warn')
    expect(result.checks.find((c) => c.id === 'replyTo')?.status).toBe('warn')
  })

  it('treats ARC-pass forwarding as a warning, not a spoof', () => {
    const result = inspectEmail(FORWARDED, 'fwd.eml')
    expect(result.checks.find((c) => c.id === 'spf')?.detailKey).toBe('email.detail.spf.forwarded')
    expect(result.checks.find((c) => c.id === 'spf')?.status).toBe('warn')
    expect(result.checks.find((c) => c.id === 'dmarc')?.status).toBe('ok')
    expect(result.checks.find((c) => c.id === 'arc')?.status).toBe('ok')
    expect(result.status).toBe('warn')
  })

  it('does not treat local unsigned-auth mail as a spoof', () => {
    const local = `Return-Path: <git@example.com>
Received: from mail.example.com ([fd4d:6169:6c63:6f77::6])
	by mailbox with LMTP
	for <user@example.com>; Thu, 13 Aug 2026 19:08:00 +0200
Received: from b1cca2acf009 (unknown [172.22.1.1])
	by mail.example.com (Postcow) with ESMTP id ABC
	for <user@example.com>; Thu, 13 Aug 2026 19:07:59 +0200
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=dkim; b=abc
Authentication-Results: mail.example.com;
	none
From: "bot" <git@example.com>
To: user@example.com
Subject: PR comment
Date: Thu, 13 Aug 2026 19:07:57 +0200
MIME-Version: 1.0
Content-Type: text/plain

hi
`
    const result = inspectEmail(local, 'local.eml')
    expect(result.status).toBe('unknown')
    expect(result.checks.find((c) => c.id === 'spf')?.detailKey).toBe('email.detail.spf.skipped')
    expect(result.checks.find((c) => c.id === 'dkim')?.detailKey).toBe(
      'email.detail.dkim.unverifiedAligned'
    )
    expect(result.checks.find((c) => c.id === 'dmarc')?.detailKey).toBe(
      'email.detail.dmarc.skipped'
    )
    expect(result.checks.find((c) => c.id === 'alignment')?.status).toBe('unknown')
    expect(result.checks.find((c) => c.id === 'tls')?.detailKey).toBe('email.detail.tls.local')
    expect(result.hops.every((h) => h.local)).toBe(true)
    expect(result.checks.find((c) => c.id === 'authResults')?.detailKey).toBe(
      'email.detail.authResults.skipped'
    )
  })

  it('rejects empty input and non-email text', () => {
    expect(() => inspectEmail('')).toThrow(EmailInspectError)
    expect(() => inspectEmail('just some notes')).toThrow(EmailInspectError)
    expect(looksLikeEmailMessage(GMAIL)).toBe(true)
  })

  it('uses i18n keys that exist', () => {
    const result = inspectEmail(GMAIL)
    expect(t(result.verdictKey as MessageKey)).not.toBe(result.verdictKey)
    for (const check of result.checks) {
      expect(t(check.titleKey as MessageKey)).not.toBe(check.titleKey)
      expect(t(check.detailKey as MessageKey, check.params)).not.toBe(check.detailKey)
    }
  })

  it('rejects truncated Outlook MSG compound files', () => {
    const ole = Uint8Array.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])
    expect(() => decodeEmailBytes(ole)).toThrow(EmailInspectError)
  })
})
