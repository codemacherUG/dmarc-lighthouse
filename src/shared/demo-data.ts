import { inspectEmail } from './email-inspect'
import { analyzeFromReports } from './analyze'
import type {
  AnalyzeResult,
  DnsCheckResult,
  EmailInspectResult,
  ForensicReportRow,
  ReportRow,
  SerializedRecord,
  SettingsPublic,
  TransportSecurityResult
} from './types'

function rec(
  overrides: Partial<SerializedRecord> &
    Pick<SerializedRecord, 'sourceIp' | 'count' | 'passesDmarc'>
): SerializedRecord {
  return {
    disposition: 'none',
    dkimResult: overrides.passesDmarc ? 'pass' : 'fail',
    spfResult: overrides.passesDmarc ? 'pass' : 'fail',
    headerFrom: 'example.com',
    dkimDomain: 'example.com',
    spfDomain: 'example.com',
    dkimSelectors: ['selector1'],
    reasons: [],
    ...overrides
  }
}

function report(input: {
  id: string
  org: string
  begin: string
  end: string
  records: SerializedRecord[]
  policy?: string
}): ReportRow {
  let total = 0
  let passing = 0
  for (const r of input.records) {
    total += r.count
    if (r.passesDmarc) passing += r.count
  }
  return {
    reportId: input.id,
    orgName: input.org,
    domain: 'example.com',
    dateBegin: input.begin,
    dateEnd: input.end,
    total,
    passing,
    failing: total - passing,
    passRate: total ? Math.round((passing / total) * 1000) / 10 : 0,
    policyP: input.policy ?? 'reject',
    records: input.records
  }
}

/** Anonymized sample data for README screenshots (RFC 5737 / 3849 docs ranges). */
export function buildDemoReports(): ReportRow[] {
  return [
    report({
      id: 'demo-g-001',
      org: 'google.com',
      begin: '2026-07-27T00:00:00.000Z',
      end: '2026-07-28T00:00:00.000Z',
      records: [rec({ sourceIp: '2001:db8:1::10', count: 12, passesDmarc: true })]
    }),
    report({
      id: 'demo-g-002',
      org: 'google.com',
      begin: '2026-07-26T00:00:00.000Z',
      end: '2026-07-27T00:00:00.000Z',
      records: [
        rec({ sourceIp: '192.0.2.10', count: 8, passesDmarc: true }),
        rec({ sourceIp: '198.51.100.20', count: 2, passesDmarc: false, disposition: 'quarantine' })
      ]
    }),
    report({
      id: 'demo-ms-001',
      org: 'Enterprise Outlook',
      begin: '2026-07-25T00:00:00.000Z',
      end: '2026-07-26T00:00:00.000Z',
      records: [
        rec({
          sourceIp: '192.0.2.40',
          count: 45,
          passesDmarc: true,
          headerFrom: 'mail.example.com',
          dkimDomain: 'mail.example.com'
        })
      ]
    }),
    report({
      id: 'demo-ms-002',
      org: 'Enterprise Outlook',
      begin: '2026-07-20T00:00:00.000Z',
      end: '2026-07-21T00:00:00.000Z',
      records: [
        rec({ sourceIp: '192.0.2.41', count: 30, passesDmarc: true }),
        rec({ sourceIp: '203.0.113.15', count: 3, passesDmarc: false, disposition: 'reject' })
      ]
    }),
    report({
      id: 'demo-yahoo-001',
      org: 'Yahoo',
      begin: '2026-07-18T00:00:00.000Z',
      end: '2026-07-19T00:00:00.000Z',
      records: [rec({ sourceIp: '198.51.100.55', count: 9, passesDmarc: true })]
    }),
    report({
      id: 'demo-gmx-001',
      org: 'GMX',
      begin: '2026-07-15T00:00:00.000Z',
      end: '2026-07-16T00:00:00.000Z',
      records: [
        rec({ sourceIp: '192.0.2.80', count: 6, passesDmarc: true }),
        rec({
          sourceIp: '203.0.113.80',
          count: 1,
          passesDmarc: false,
          dkimDomain: 'sendgrid.net',
          spfDomain: 'em1234.sendgrid.net'
        })
      ]
    }),
    report({
      id: 'demo-g-003',
      org: 'google.com',
      begin: '2026-07-10T00:00:00.000Z',
      end: '2026-07-11T00:00:00.000Z',
      records: [rec({ sourceIp: '2001:db8:2::22', count: 15, passesDmarc: true })]
    }),
    report({
      id: 'demo-ms-003',
      org: 'Enterprise Outlook',
      begin: '2026-07-05T00:00:00.000Z',
      end: '2026-07-06T00:00:00.000Z',
      records: [rec({ sourceIp: '192.0.2.40', count: 22, passesDmarc: true })]
    }),
    report({
      id: 'demo-g-004',
      org: 'google.com',
      begin: '2026-06-28T00:00:00.000Z',
      end: '2026-06-29T00:00:00.000Z',
      records: [
        rec({ sourceIp: '192.0.2.10', count: 11, passesDmarc: true }),
        rec({
          sourceIp: '198.51.100.20',
          count: 4,
          passesDmarc: false,
          reasons: [{ type: 'forwarded', comment: null }]
        })
      ]
    }),
    report({
      id: 'demo-yahoo-002',
      org: 'Yahoo',
      begin: '2026-06-20T00:00:00.000Z',
      end: '2026-06-21T00:00:00.000Z',
      records: [rec({ sourceIp: '198.51.100.55', count: 7, passesDmarc: true })]
    }),
    report({
      id: 'demo-gmx-002',
      org: 'GMX',
      begin: '2026-06-12T00:00:00.000Z',
      end: '2026-06-13T00:00:00.000Z',
      records: [rec({ sourceIp: '192.0.2.80', count: 5, passesDmarc: true })]
    }),
    report({
      id: 'demo-ms-004',
      org: 'Enterprise Outlook',
      begin: '2026-06-01T00:00:00.000Z',
      end: '2026-06-02T00:00:00.000Z',
      records: [
        rec({ sourceIp: '192.0.2.40', count: 18, passesDmarc: true }),
        rec({
          sourceIp: '203.0.113.15',
          count: 2,
          passesDmarc: false,
          disposition: 'quarantine',
          headerFrom: 'newsletter.example.com'
        })
      ]
    })
  ]
}

export function buildDemoForensic(): ForensicReportRow[] {
  return [
    {
      id: 'forensic-demo-1',
      reportId: 'arf-001',
      orgName: 'google.com',
      reportedDomain: 'example.com',
      arrivalDate: '2026-07-28T09:15:00.000Z',
      sourceIp: '203.0.113.50',
      authFailure: 'dmarc',
      deliveryResult: 'delivered',
      envelopeFrom: 'spoof@evil.example',
      headerFrom: 'billing@example.com',
      originalRcptTo: 'user@example.com',
      authenticationResults: 'dmarc=fail (p=reject)',
      subject: 'Invoice attached',
      feedbackType: 'auth-failure'
    },
    {
      id: 'forensic-demo-2',
      reportId: 'arf-002',
      orgName: 'Enterprise Outlook',
      reportedDomain: 'example.com',
      arrivalDate: '2026-07-22T14:40:00.000Z',
      sourceIp: '198.51.100.90',
      authFailure: 'spf',
      deliveryResult: 'spam',
      envelopeFrom: 'noreply@phish.example',
      headerFrom: 'support@example.com',
      originalRcptTo: 'info@example.com',
      authenticationResults: 'spf=fail; dmarc=fail',
      subject: 'Password reset',
      feedbackType: 'auth-failure'
    },
    {
      id: 'forensic-demo-3',
      reportId: 'arf-003',
      orgName: 'Yahoo',
      reportedDomain: 'example.com',
      arrivalDate: '2026-07-12T07:05:00.000Z',
      sourceIp: '192.0.2.200',
      authFailure: 'dkim',
      deliveryResult: 'reject',
      envelopeFrom: 'mailer@bad.example',
      headerFrom: 'hello@example.com',
      originalRcptTo: 'sales@example.com',
      authenticationResults: 'dkim=fail; dmarc=fail',
      subject: 'Urgent request',
      feedbackType: 'auth-failure'
    }
  ]
}

export function buildDemoAnalyzeResult(): AnalyzeResult {
  return analyzeFromReports(buildDemoReports(), {
    fromCache: true,
    newReports: 0,
    forensicReports: buildDemoForensic()
  })
}

export function buildDemoSettings(): SettingsPublic {
  return {
    activeAccountId: 'demo-account-1',
    accounts: [
      {
        id: 'demo-account-1',
        name: 'example.com',
        label: 'example.com',
        suggestedName: 'example.com',
        provider: 'custom',
        authMode: 'password',
        host: 'mail.example.com',
        port: 993,
        secure: true,
        user: 'dmarc@example.com',
        mailbox: 'INBOX',
        archiveMailbox: 'Archive/Aggregate',
        subjectFilter: 'Report Domain',
        hasPassword: true,
        hasOAuth: false,
        markSeenAfterFetch: false
      },
      {
        id: 'demo-account-2',
        name: 'contoso.example',
        label: 'contoso.example',
        suggestedName: 'contoso.example',
        provider: 'outlook',
        authMode: 'oauth',
        host: 'outlook.office365.com',
        port: 993,
        secure: true,
        user: 'reports@contoso.example',
        mailbox: 'INBOX',
        archiveMailbox: '',
        subjectFilter: 'Report Domain',
        hasPassword: false,
        hasOAuth: true,
        markSeenAfterFetch: false
      }
    ],
    global: {
      autoFetchMinutes: 60,
      notifyOnFail: true,
      passRateAlertThreshold: 90,
      notifyNewSource: true,
      ignoredSources: '192.0.2.*\n198.51.100.1',
      runInTray: true,
      openAtLogin: true,
      language: 'de',
      theme: 'auto',
      oauthGoogleClientId: '',
      oauthMicrosoftClientId: '',
      enrichmentEnabled: true,
      geoIpOnlineFallback: false,
      maxmindLicenseKey: '',
      hasMaxmindLicenseKey: false,
      dnsblEnabled: true,
      cloudRangesEnabled: true,
      rdapEnabled: true,
      hideGoogleNoise: false,
      pdfMonthlyEnabled: true,
      pdfMonthlyDir: '',
      pdfMonthlyLastRun: '2026-08-01T06:00:00.000Z'
    }
  }
}

export const DEMO_DNS_HTML = `<strong>example.com</strong><br />DMARC: p=reject · rua=mailto:dmarc@example.com · ruf=mailto:dmarc@example.com<br /><span class="mono">SPF: v=spf1 include:_spf.example.net -all</span><br />DKIM selector1: gefunden`

/** Transport check for the DNS screenshot: MTA-STS enforced, DANE only on one MX. */
export const DEMO_TRANSPORT: TransportSecurityResult = {
  domain: 'example.com',
  tlsrpt: {
    found: true,
    records: ['v=TLSRPTv1; rua=mailto:tlsrpt@example.com'],
    rua: ['mailto:tlsrpt@example.com']
  },
  mtaSts: {
    found: true,
    id: '20260728T080000',
    records: ['v=STSv1; id=20260728T080000'],
    policyUrl: 'https://mta-sts.example.com/.well-known/mta-sts.txt',
    policy: {
      version: 'STSv1',
      mode: 'enforce',
      mx: ['mx1.example.net', 'mx2.example.net'],
      maxAgeSeconds: 1209600
    }
  },
  dane: {
    mx: [
      { host: 'mx1.example.net', preference: 10, tlsa: ['3 1 1 a1b2c3d4…'], found: true },
      { host: 'mx2.example.net', preference: 20, tlsa: [], found: false }
    ]
  },
  status: 'warn',
  reasons: [
    { key: 'transport.reason.danePartial', level: 'warn' },
    { key: 'transport.reason.tlsrptOk', level: 'ok' },
    { key: 'transport.reason.mtaStsEnforce', level: 'ok' }
  ],
  checkedAt: '2026-07-28T08:00:00.000Z'
}

/** DNS answer for the rollout screenshot: monitoring only, so a next step exists. */
export const DEMO_ROLLOUT_DNS: DnsCheckResult = {
  domain: 'example.com',
  dmarc: {
    found: true,
    records: ['v=DMARC1; p=none; rua=mailto:dmarc@example.com; adkim=r; aspf=r'],
    policy: 'none',
    rua: 'mailto:dmarc@example.com',
    ruf: null
  },
  spf: { found: true, records: ['v=spf1 include:_spf.example.net -all'] },
  dkim: { selectors: [{ selector: 'selector1', found: true, record: 'v=DKIM1; k=rsa; p=MIIB…' }] },
  checkedAt: '2026-07-28T08:00:00.000Z'
}

const DEMO_EMAIL_SOURCE = `Return-Path: <newsletter@example.com>
Received: from mail.example.net ([172.22.1.253])
	by dovecot with LMTP
	id abc
	for <user@example.com>; Thu, 13 Aug 2026 19:01:02 +0200
Received: from smtp.example.com (smtp.example.com [192.0.2.10])
        by mail.example.net with ESMTPS id xyz
        for <user@example.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 13 Aug 2026 10:00:58 -0700
Authentication-Results: mail.example.net;
       dkim=pass header.i=@example.com header.s=selector1 header.b=abcd;
       spf=pass (mail.example.net: domain of newsletter@example.com designates 192.0.2.10 as permitted sender) smtp.mailfrom=newsletter@example.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com
Received-SPF: pass (mail.example.net: domain of newsletter@example.com designates 192.0.2.10 as permitted sender) client-ip=192.0.2.10;
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1; c=relaxed/relaxed;
        h=from:to:subject:date:message-id; bh=abc; b=def
From: Example News <newsletter@example.com>
To: User <user@example.com>
Subject: August Update
Date: Thu, 13 Aug 2026 17:00:00 +0000
Message-ID: <news@example.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Hello
`

/** Anonymized inspection result for the email-inspect screenshot. */
export function buildDemoEmailInspect(): EmailInspectResult {
  const result = inspectEmail(DEMO_EMAIL_SOURCE, 'newsletter.eml')
  const demoInfo = (
    ip: string,
    ptr: string,
    provider: string,
    city: string,
    countryCode: string
  ): NonNullable<EmailInspectResult['hops'][number]['ipInfo']> => ({
    ip,
    ptr,
    provider,
    senderKind: 'mailbox',
    country: null,
    countryCode,
    city,
    lat: null,
    lon: null,
    asn: 64496,
    asOrg: 'Example Net',
    cloudProvider: null,
    dnsblHits: [],
    geoSource: 'none'
  })
  return {
    ...result,
    hops: result.hops.map((hop) => {
      if (hop.fromIp === '192.0.2.10') {
        return {
          ...hop,
          ipInfo: demoInfo('192.0.2.10', 'smtp.example.com', 'Example Net', 'Berlin', 'DE')
        }
      }
      if (hop.fromIp === '172.22.1.253') {
        return {
          ...hop,
          ipInfo: demoInfo('172.22.1.253', 'mail.example.net', 'Example Net', 'Berlin', 'DE')
        }
      }
      return hop
    })
  }
}
