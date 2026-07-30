import { analyzeFromReports } from './analyze'
import type {
  AnalyzeResult,
  ForensicReportRow,
  ReportRow,
  SerializedRecord,
  SettingsPublic
} from './types'

function rec(overrides: Partial<SerializedRecord> & Pick<SerializedRecord, 'sourceIp' | 'count' | 'passesDmarc'>): SerializedRecord {
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
        rec({ sourceIp: '203.0.113.80', count: 1, passesDmarc: false })
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
        rec({ sourceIp: '198.51.100.20', count: 4, passesDmarc: false })
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
      openAtLogin: false,
      language: 'de',
      oauthGoogleClientId: '',
      oauthMicrosoftClientId: '',
      enrichmentEnabled: true,
      geoIpOnlineFallback: false,
      maxmindLicenseKey: '',
      dnsblEnabled: true,
      cloudRangesEnabled: true,
      rdapEnabled: true
    }
  }
}

export const DEMO_DNS_HTML = `<strong>example.com</strong><br />DMARC: p=reject · rua=mailto:dmarc@example.com · ruf=mailto:dmarc@example.com<br /><span class="mono">SPF: v=spf1 include:_spf.example.net -all</span><br />DKIM selector1: gefunden`
