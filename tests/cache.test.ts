import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { DatabaseSync } from 'node:sqlite'
import { afterEach, describe, expect, it } from 'vitest'
import {
  acknowledgePendingSourceIps,
  accountKeyFor,
  addPendingSourceIps,
  LOCAL_IMPORT_ACCOUNT_KEY,
  clearCache,
  clearKnownIpsResetPending,
  closeCacheDb,
  getIpEnrichment,
  getDnsHistory,
  importReports,
  loadCachedReports,
  mergeReports,
  recordDnsHistory,
  recordTransportHistory,
  reseedKnownIps,
  resetKnownSourceIps,
  saveCache,
  setCacheUserDataForTests,
  upsertIpEnrichment,
  upsertSendingService
} from '../src/main/cache'
import type { DnsCheckResult, ReportRow, TransportSecurityResult } from '../src/shared/types'
import { loadCachedAnalyzeResult } from '../src/main/imap'
import { clearIpInfoMemoryCache } from '../src/main/ipinfo'

function sampleReport(id: string): ReportRow {
  return {
    reportId: id,
    orgName: 'google.com',
    domain: 'example.com',
    dateBegin: '2026-07-01T00:00:00.000Z',
    dateEnd: '2026-07-02T00:00:00.000Z',
    total: 2,
    passing: 1,
    failing: 1,
    passRate: 50,
    policyP: 'none',
    records: [
      {
        sourceIp: '192.0.2.1',
        count: 1,
        disposition: 'none',
        dkimResult: 'pass',
        spfResult: 'pass',
        headerFrom: 'example.com',
        dkimDomain: 'example.com',
        spfDomain: 'example.com',
        dkimRawResult: 'pass',
        spfRawResult: 'pass',
        dkimSelectors: ['s1'],
        passesDmarc: true,
        reasons: []
      }
    ]
  }
}

function reportWithFailureRate(
  id: string,
  dateBegin: string,
  dateEnd: string,
  total: number,
  failing: number
): ReportRow {
  const report = sampleReport(id)
  return {
    ...report,
    dateBegin,
    dateEnd,
    total,
    failing,
    passing: total - failing,
    passRate: Math.round(((total - failing) / total) * 1000) / 10
  }
}

function dnsResult(input: {
  checkedAt: string
  dmarc?: string
  spf?: string
  dkim?: Array<{ selector: string; record: string | null }>
}): DnsCheckResult {
  return {
    domain: 'example.com',
    checkedAt: input.checkedAt,
    dmarc: {
      found: Boolean(input.dmarc),
      records: input.dmarc ? [input.dmarc] : [],
      policy: input.dmarc ? 'none' : null,
      rua: null,
      ruf: null,
      host: '_dmarc.example.com'
    },
    spf: { found: Boolean(input.spf), records: input.spf ? [input.spf] : [] },
    dkim: {
      selectors: (input.dkim ?? []).map((item) => ({
        selector: item.selector,
        found: Boolean(item.record),
        record: item.record
      }))
    },
    bimi: {
      domain: 'example.com',
      selector: 'default',
      host: 'default._bimi.example.com',
      found: false,
      records: [],
      location: null,
      authority: null
    }
  }
}

function transportResult(checkedAt: string, mode: 'testing' | 'enforce'): TransportSecurityResult {
  return {
    domain: 'example.com',
    checkedAt,
    tlsrpt: {
      found: true,
      records: ['v=TLSRPTv1; rua=mailto:tls@example.com'],
      rua: ['mailto:tls@example.com']
    },
    mtaSts: {
      found: true,
      id: checkedAt,
      records: [`v=STSv1; id=${checkedAt}`],
      policyUrl: 'https://mta-sts.example.com/.well-known/mta-sts.txt',
      policy: { version: 'STSv1', mode, mx: ['mail.example.com'], maxAgeSeconds: 604800 }
    },
    dane: { mx: [] },
    status: mode === 'enforce' ? 'ok' : 'warn',
    reasons: []
  }
}

describe('sqlite cache', () => {
  let dir: string

  afterEach(() => {
    clearIpInfoMemoryCache()
    closeCacheDb()
    setCacheUserDataForTests(null)
    if (dir) rmSync(dir, { recursive: true, force: true })
  })

  it('saves and loads reports + forensic rows', () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-cache-'))
    setCacheUserDataForTests(dir)

    saveCache({
      accountKey: 'acct1',
      reports: [sampleReport('r1')],
      forensicReports: [
        {
          id: 'f1',
          reportId: null,
          orgName: 'google.com',
          reportedDomain: 'example.com',
          arrivalDate: '2026-07-30T10:00:00.000Z',
          sourceIp: '203.0.113.1',
          authFailure: 'dmarc',
          deliveryResult: 'delivered',
          envelopeFrom: 'a@evil.example',
          headerFrom: 'a@evil.example',
          originalRcptTo: 'u@example.com',
          authenticationResults: 'dmarc=fail',
          subject: 'Hi',
          feedbackType: 'auth-failure'
        }
      ],
      lastUid: 42,
      lastUidArchive: 7,
      lastFailingTotal: 1,
      knownSourceIps: ['192.0.2.1']
    })

    const loaded = loadCachedReports('acct1')
    expect(loaded.meta.lastUid).toBe(42)
    expect(loaded.meta.lastUidArchive).toBe(7)
    expect(loaded.meta.knownSourceIps).toEqual(['192.0.2.1', '203.0.113.1'])
    expect(loaded.reports).toHaveLength(1)
    expect(loaded.reports[0].records[0].dkimSelectors).toEqual(['s1'])
    expect(loaded.reports[0].records[0].dkimRawResult).toBe('pass')
    expect(loaded.reports[0].records[0].spfRawResult).toBe('pass')
    expect(loaded.forensicReports).toHaveLength(1)
    expect(loaded.forensicReports[0].sourceIp).toBe('203.0.113.1')
  })

  it('migrates version 10 report records to retain raw authentication results', () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-cache-'))
    const cacheDir = join(dir, 'cache')
    mkdirSync(cacheDir, { recursive: true })
    const databasePath = join(cacheDir, 'dmarc-lighthouse.sqlite')
    const legacy = new DatabaseSync(databasePath)
    legacy.exec(`
      CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      INSERT INTO schema_meta(key, value) VALUES ('version', '10');
      CREATE TABLE cache_meta (
        account_key TEXT PRIMARY KEY,
        last_uid INTEGER NOT NULL DEFAULT 0,
        last_uid_archive INTEGER NOT NULL DEFAULT 0,
        last_fetch_at TEXT,
        last_failing_total INTEGER NOT NULL DEFAULT 0,
        known_ips_reset_pending INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE report_records (
        account_key TEXT NOT NULL,
        report_id TEXT NOT NULL,
        ordinal INTEGER NOT NULL,
        source_ip TEXT NOT NULL,
        count INTEGER NOT NULL,
        disposition TEXT,
        dkim_result TEXT,
        spf_result TEXT,
        header_from TEXT,
        dkim_domain TEXT,
        spf_domain TEXT,
        passes_dmarc INTEGER NOT NULL,
        reasons_json TEXT NOT NULL,
        selectors_json TEXT NOT NULL,
        PRIMARY KEY (account_key, report_id, ordinal)
      );
    `)
    legacy.close()
    setCacheUserDataForTests(dir)

    loadCachedReports('acct1')
    closeCacheDb()

    const migrated = new DatabaseSync(databasePath)
    const columns = migrated.prepare('PRAGMA table_info(report_records)').all() as Array<{
      name: string
    }>
    const version = migrated
      .prepare("SELECT value FROM schema_meta WHERE key = 'version'")
      .get() as { value: string }
    migrated.close()
    expect(columns.map((column) => column.name)).toEqual(
      expect.arrayContaining(['dkim_raw_result', 'spf_raw_result'])
    )
    expect(version.value).toBe('12')
  })

  it('persists pending source IPs until they are acknowledged or the cache is cleared', () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-cache-'))
    setCacheUserDataForTests(dir)
    saveCache({
      accountKey: 'acct1',
      reports: [sampleReport('r1')],
      lastUid: 42,
      lastFailingTotal: 1,
      knownSourceIps: ['192.0.2.1']
    })

    addPendingSourceIps('acct1', ['203.0.113.10', '203.0.113.20'])
    closeCacheDb()
    expect(loadCachedReports('acct1').meta.pendingSourceIps).toEqual([
      '203.0.113.10',
      '203.0.113.20'
    ])

    acknowledgePendingSourceIps('acct1', ['203.0.113.10'])
    expect(loadCachedReports('acct1').meta.pendingSourceIps).toEqual(['203.0.113.20'])

    clearCache('acct1')
    expect(loadCachedReports('acct1').meta.pendingSourceIps).toEqual([])
  })

  it('migrates historical sources for non-known services into the pending queue', () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-cache-'))
    setCacheUserDataForTests(dir)
    const accountKey = 'pre-pending-services'
    saveCache({
      accountKey,
      reports: [sampleReport('historical-service')],
      lastUid: 42,
      lastFailingTotal: 1,
      knownSourceIps: ['192.0.2.1']
    })
    upsertIpEnrichment([
      {
        ip: '192.0.2.1',
        ptr: 'mail.example.net',
        provider: 'Example Mail',
        senderKind: 'esp',
        country: null,
        countryCode: null,
        city: null,
        lat: null,
        lon: null,
        asn: 64500,
        asOrg: 'Example Network',
        cloudProvider: null,
        dnsblHits: [],
        geoSource: 'none'
      }
    ])
    upsertSendingService({
      provider: 'Example Mail',
      domain: 'example.com',
      cidr: null,
      asn: null,
      status: 'investigate',
      note: null,
      team: null
    })
    expect(loadCachedReports(accountKey).meta.pendingSourceIps).toEqual([])

    closeCacheDb()
    const databasePath = join(dir, 'cache', 'dmarc-lighthouse.sqlite')
    const legacy = new DatabaseSync(databasePath)
    legacy.prepare("UPDATE schema_meta SET value = '11' WHERE key = 'version'").run()
    legacy.close()

    expect(loadCachedReports(accountKey).meta.pendingSourceIps).toEqual(['192.0.2.1'])
  })

  it('reconstructs pending sending sources when cached analysis is loaded after restart', async () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-cache-'))
    setCacheUserDataForTests(dir)
    const settings = {
      provider: 'custom' as const,
      host: 'imap.example.com',
      port: 993,
      secure: true,
      user: 'user@example.com',
      authMode: 'password' as const,
      mailbox: 'INBOX',
      archiveMailbox: '',
      subjectFilter: '',
      markSeenAfterFetch: false
    }
    const accountKey = accountKeyFor(settings.user, settings.host, settings.mailbox)
    saveCache({
      accountKey,
      reports: [sampleReport('r1')],
      lastUid: 42,
      lastFailingTotal: 1,
      knownSourceIps: ['192.0.2.1']
    })
    addPendingSourceIps(accountKey, ['192.0.2.1'])
    upsertIpEnrichment([
      {
        ip: '192.0.2.1',
        ptr: 'mail.example.net',
        provider: 'Example Mail',
        senderKind: 'esp',
        country: null,
        countryCode: null,
        city: null,
        lat: null,
        lon: null,
        asn: 64500,
        asOrg: 'Example Network',
        cloudProvider: null,
        dnsblHits: [],
        geoSource: 'none'
      }
    ])
    closeCacheDb()
    clearIpInfoMemoryCache()

    expect(loadCachedReports(accountKey).meta.pendingSourceIps).toEqual(['192.0.2.1'])
    expect(getIpEnrichment(['192.0.2.1']).get('192.0.2.1')?.provider).toBe('Example Mail')
    const result = await loadCachedAnalyzeResult(settings)
    expect(result.newSourceIps).toEqual([])
    expect(result.newSendingSources).toEqual([
      {
        provider: 'Example Mail',
        domain: 'example.com',
        ips: ['192.0.2.1'],
        status: 'unknown',
        asn: 64500
      }
    ])
  })

  it('keeps mailbox forwarding noise pending until its sender service is resolved', async () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-cache-'))
    setCacheUserDataForTests(dir)
    const settings = {
      provider: 'custom' as const,
      host: 'imap.example.com',
      port: 993,
      secure: true,
      user: 'user@example.com',
      authMode: 'password' as const,
      mailbox: 'INBOX',
      archiveMailbox: '',
      subjectFilter: '',
      markSeenAfterFetch: false
    }
    const accountKey = accountKeyFor(settings.user, settings.host, settings.mailbox)
    const noiseIp = '2a00:1450:4864:20::346'
    const noiseReport = sampleReport('noise')
    noiseReport.records = [
      {
        ...noiseReport.records[0],
        sourceIp: noiseIp,
        dkimResult: 'fail',
        spfResult: 'fail',
        passesDmarc: false,
        reasons: [{ type: 'local_policy', comment: 'arc=pass' }]
      }
    ]
    saveCache({
      accountKey,
      reports: [noiseReport],
      lastUid: 42,
      lastFailingTotal: 1,
      knownSourceIps: [noiseIp]
    })
    addPendingSourceIps(accountKey, [noiseIp])
    upsertIpEnrichment([
      {
        ip: noiseIp,
        ptr: 'mailout.gmx.net',
        provider: 'GMX',
        senderKind: 'mailbox',
        country: null,
        countryCode: null,
        city: null,
        lat: null,
        lon: null,
        asn: 3209,
        asOrg: 'GMX GmbH',
        cloudProvider: null,
        dnsblHits: [],
        geoSource: 'none'
      }
    ])

    const result = await loadCachedAnalyzeResult(settings)
    expect(result.newSendingSources).toEqual([
      {
        provider: 'GMX',
        domain: 'example.com',
        ips: [noiseIp],
        status: 'unknown',
        asn: 3209
      }
    ])
    expect(loadCachedReports(accountKey).meta.pendingSourceIps).toEqual([noiseIp])
  })

  it('migrates legacy JSON cache files', () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-cache-'))
    const cacheDir = join(dir, 'cache')
    mkdirSync(cacheDir, { recursive: true })
    writeFileSync(
      join(cacheDir, 'legacykey.json'),
      JSON.stringify({
        version: 1,
        accountKey: 'legacykey',
        lastUid: 9,
        lastFetchAt: '2026-07-01T00:00:00.000Z',
        lastFailingTotal: 3,
        knownSourceIps: ['10.0.0.1'],
        reports: [sampleReport('legacy-r')]
      })
    )
    setCacheUserDataForTests(dir)

    const loaded = loadCachedReports('legacykey')
    expect(loaded.reports[0].reportId).toBe('legacy-r')
    expect(loaded.meta.lastUid).toBe(9)
    expect(loaded.meta.knownSourceIps).toEqual(['10.0.0.1'])
  })

  it('clears an account cache', () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-cache-'))
    setCacheUserDataForTests(dir)
    saveCache({
      accountKey: 'acct1',
      reports: [sampleReport('r1')],
      lastUid: 5,
      lastFailingTotal: 1,
      knownSourceIps: ['192.0.2.1']
    })
    clearCache('acct1')
    const loaded = loadCachedReports('acct1')
    expect(loaded.reports).toEqual([])
    expect(loaded.meta.lastUid).toBe(0)
  })

  it('resets known source IPs and flags a pending reset until reseeded', () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-cache-'))
    setCacheUserDataForTests(dir)
    saveCache({
      accountKey: 'acct1',
      reports: [sampleReport('r1')],
      lastUid: 5,
      lastFailingTotal: 1,
      knownSourceIps: ['192.0.2.1']
    })

    resetKnownSourceIps('acct1')
    let loaded = loadCachedReports('acct1')
    expect(loaded.meta.knownSourceIps).toEqual([])
    expect(loaded.meta.knownIpsResetPending).toBe(true)
    // Reports and the UID watermark stay untouched by a reset.
    expect(loaded.reports).toHaveLength(1)
    expect(loaded.meta.lastUid).toBe(5)

    reseedKnownIps('acct1', ['192.0.2.1', '198.51.100.9'])
    loaded = loadCachedReports('acct1')
    expect(loaded.meta.knownSourceIps).toEqual(['192.0.2.1', '198.51.100.9'])
    expect(loaded.meta.knownIpsResetPending).toBe(false)
  })

  it('clearKnownIpsResetPending clears the flag without touching known IPs', () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-cache-'))
    setCacheUserDataForTests(dir)
    saveCache({
      accountKey: 'acct1',
      reports: [sampleReport('r1')],
      lastUid: 5,
      lastFailingTotal: 1,
      knownSourceIps: ['192.0.2.1']
    })
    resetKnownSourceIps('acct1')
    clearKnownIpsResetPending('acct1')
    const loaded = loadCachedReports('acct1')
    expect(loaded.meta.knownIpsResetPending).toBe(false)
    expect(loaded.meta.knownSourceIps).toEqual([])
  })

  it('merges reports by reportId', () => {
    const merged = mergeReports([sampleReport('a')], [sampleReport('a'), sampleReport('b')])
    expect(merged.map((r) => r.reportId).sort()).toEqual(['a', 'b'])
  })

  it('imports reports without touching the UID watermarks', () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-cache-'))
    setCacheUserDataForTests(dir)
    saveCache({
      accountKey: 'acct1',
      reports: [sampleReport('r1')],
      lastUid: 42,
      lastUidArchive: 7,
      lastFailingTotal: 1,
      knownSourceIps: ['192.0.2.1']
    })

    const imported = sampleReport('r2')
    imported.records = [{ ...imported.records[0], sourceIp: '198.51.100.9' }]
    const stored = importReports({ accountKey: 'acct1', reports: [imported] })

    expect(stored).toEqual({ addedReports: 1, updatedReports: 0, addedForensic: 0 })
    const loaded = loadCachedReports('acct1')
    expect(loaded.reports.map((r) => r.reportId).sort()).toEqual(['r1', 'r2'])
    expect(loaded.meta.lastUid).toBe(42)
    expect(loaded.meta.lastUidArchive).toBe(7)
    expect(loaded.meta.knownSourceIps).toEqual(['192.0.2.1', '198.51.100.9'])
    // Failing baseline follows the cache so imported failures do not trigger alerts.
    expect(loaded.meta.lastFailingTotal).toBe(2)
  })

  it('replaces an already cached report on re-import', () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-cache-'))
    setCacheUserDataForTests(dir)
    importReports({ accountKey: 'acct1', reports: [sampleReport('r1')] })

    const again = sampleReport('r1')
    again.records = [...again.records, { ...again.records[0], sourceIp: '198.51.100.9' }]
    const stored = importReports({ accountKey: 'acct1', reports: [again] })

    expect(stored).toEqual({ addedReports: 0, updatedReports: 1, addedForensic: 0 })
    const loaded = loadCachedReports('acct1')
    expect(loaded.reports).toHaveLength(1)
    expect(loaded.reports[0].records).toHaveLength(2)
  })

  it('imports into a fresh account slot', () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-cache-'))
    setCacheUserDataForTests(dir)
    importReports({
      accountKey: LOCAL_IMPORT_ACCOUNT_KEY,
      reports: [sampleReport('r1')]
    })
    const loaded = loadCachedReports(LOCAL_IMPORT_ACCOUNT_KEY)
    expect(loaded.reports).toHaveLength(1)
    expect(loaded.meta.lastUid).toBe(0)
  })

  it('keeps permanent DNS history and detects DNS drift outside cache clearing', () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-cache-'))
    setCacheUserDataForTests(dir)

    recordDnsHistory(
      dnsResult({
        checkedAt: '2026-08-19T08:00:00.000Z',
        dmarc: 'v=DMARC1; p=none',
        spf: 'v=spf1 include:_spf.old.example -all',
        dkim: [{ selector: 's1', record: 'v=DKIM1; p=old' }]
      })
    )
    recordDnsHistory(
      dnsResult({
        checkedAt: '2026-08-19T10:00:00.000Z',
        dmarc: 'v=DMARC1; p=quarantine',
        spf: 'v=spf1 -all',
        dkim: [
          { selector: 's1', record: 'v=DKIM1; p=old' },
          { selector: 's2', record: 'v=DKIM1; p=new' }
        ]
      })
    )

    const history = getDnsHistory('example.com')
    expect(history.snapshots).toHaveLength(2)
    expect(history.drifts.map((event) => event.title)).toEqual(
      expect.arrayContaining(['DMARC geändert', 'SPF include entfernt', 'Neuer DKIM-Key'])
    )

    clearCache('acct1')
    expect(getDnsHistory('example.com').snapshots).toHaveLength(2)
  })

  it('correlates a DNS drift with a later DMARC fail-rate increase', () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-cache-'))
    setCacheUserDataForTests(dir)
    saveCache({
      accountKey: 'acct1',
      reports: [
        reportWithFailureRate(
          'before',
          '2026-08-19T08:00:00.000Z',
          '2026-08-19T09:00:00.000Z',
          1000,
          3
        ),
        reportWithFailureRate(
          'after',
          '2026-08-19T10:00:00.000Z',
          '2026-08-19T12:00:00.000Z',
          1000,
          84
        )
      ],
      lastUid: 1,
      lastFailingTotal: 87,
      knownSourceIps: []
    })
    recordDnsHistory(
      dnsResult({
        checkedAt: '2026-08-19T08:30:00.000Z',
        spf: 'v=spf1 include:_spf.old.example -all'
      })
    )
    recordDnsHistory(dnsResult({ checkedAt: '2026-08-19T10:00:00.000Z', spf: 'v=spf1 -all' }))

    const [correlation] = getDnsHistory('example.com').correlations
    expect(correlation).toMatchObject({
      beforeReportId: 'before',
      afterReportId: 'after',
      beforeFailRate: 0.3,
      afterFailRate: 8.4,
      deltaPercentagePoints: 8.1,
      hoursAfter: 2
    })
  })

  it('excludes reports that overlap a DNS drift from the before/after comparison', () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-cache-'))
    setCacheUserDataForTests(dir)
    saveCache({
      accountKey: 'acct1',
      reports: [
        reportWithFailureRate(
          'before',
          '2026-08-19T08:00:00.000Z',
          '2026-08-19T09:00:00.000Z',
          1000,
          3
        ),
        reportWithFailureRate(
          'overlaps',
          '2026-08-19T09:00:00.000Z',
          '2026-08-19T11:00:00.000Z',
          1000,
          900
        ),
        reportWithFailureRate(
          'after',
          '2026-08-19T11:00:00.000Z',
          '2026-08-19T12:00:00.000Z',
          1000,
          84
        )
      ],
      lastUid: 1,
      lastFailingTotal: 987,
      knownSourceIps: []
    })
    recordDnsHistory(dnsResult({ checkedAt: '2026-08-19T08:30:00.000Z', spf: 'v=spf1 old' }))
    recordDnsHistory(dnsResult({ checkedAt: '2026-08-19T10:00:00.000Z', spf: 'v=spf1 new' }))

    const [correlation] = getDnsHistory('example.com').correlations
    expect(correlation).toMatchObject({
      beforeReportId: 'before',
      afterReportId: 'after',
      afterFailRate: 8.4
    })
  })

  it('detects MTA-STS policy drift in transport history', () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-cache-'))
    setCacheUserDataForTests(dir)

    recordTransportHistory(transportResult('2026-08-19T08:00:00.000Z', 'testing'))
    recordTransportHistory(transportResult('2026-08-19T09:00:00.000Z', 'enforce'))

    expect(getDnsHistory('example.com').drifts.map((event) => event.title)).toContain(
      'MTA-STS Policy geändert'
    )
  })

  it('appends newly saved reports without dropping the rest', () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-cache-'))
    setCacheUserDataForTests(dir)
    saveCache({
      accountKey: 'acct1',
      reports: [sampleReport('r1')],
      lastUid: 1,
      lastFailingTotal: 1,
      knownSourceIps: ['192.0.2.1']
    })
    const second = sampleReport('r2')
    second.records = [{ ...second.records[0], sourceIp: '198.51.100.9' }]
    saveCache({
      accountKey: 'acct1',
      reports: [second],
      lastUid: 9,
      lastFailingTotal: 2,
      knownSourceIps: ['198.51.100.9']
    })

    const loaded = loadCachedReports('acct1')
    expect(loaded.reports.map((r) => r.reportId).sort()).toEqual(['r1', 'r2'])
    expect(loaded.reports.find((r) => r.reportId === 'r1')?.records[0].sourceIp).toBe('192.0.2.1')
    expect(loaded.reports.find((r) => r.reportId === 'r2')?.records[0].sourceIp).toBe(
      '198.51.100.9'
    )
    expect(loaded.meta.lastUid).toBe(9)
    expect(loaded.meta.knownSourceIps).toEqual(['192.0.2.1', '198.51.100.9'])
  })
})
