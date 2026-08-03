import { app } from 'electron'
import { createHash } from 'crypto'
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync } from 'fs'
import { join } from 'path'
import { DatabaseSync } from 'node:sqlite'
import type {
  DnsCheckResult,
  ForensicReportRow,
  IpInfo,
  ReportRow,
  SerializedRecord
} from '../shared/types'

export interface CacheMeta {
  accountKey: string
  lastUid: number
  /** UID watermark for the optional archive mailbox (when dual-folder fetch is used). */
  lastUidArchive: number
  lastFetchAt: string | null
  lastFailingTotal: number
  knownSourceIps: string[]
}

interface LegacyCacheFile {
  version: 1
  accountKey: string
  lastUid: number
  lastFetchAt: string | null
  lastFailingTotal: number
  knownSourceIps?: string[]
  reports: ReportRow[]
}

let db: DatabaseSync | null = null
/** Test-only override for the userData root (avoids needing Electron `app`). */
let userDataOverride: string | null = null

export function setCacheUserDataForTests(dir: string | null): void {
  closeCacheDb()
  userDataOverride = dir
}

function cacheDir(): string {
  const root = userDataOverride ?? app.getPath('userData')
  const dir = join(root, 'cache')
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
  return dir
}

function dbPath(): string {
  return join(cacheDir(), 'dmarcviewer.sqlite')
}

function normalizeRecord(rec: SerializedRecord): SerializedRecord {
  return {
    ...rec,
    reasons: rec.reasons ?? [],
    dkimSelectors: rec.dkimSelectors ?? []
  }
}

function normalizeReport(r: ReportRow): ReportRow {
  return {
    ...r,
    records: (r.records ?? []).map(normalizeRecord)
  }
}

function openDb(): DatabaseSync {
  if (db) return db
  const path = dbPath()
  db = new DatabaseSync(path)
  db.exec('PRAGMA journal_mode = WAL;')
  db.exec('PRAGMA foreign_keys = ON;')
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS cache_meta (
      account_key TEXT PRIMARY KEY,
      last_uid INTEGER NOT NULL DEFAULT 0,
      last_uid_archive INTEGER NOT NULL DEFAULT 0,
      last_fetch_at TEXT,
      last_failing_total INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS known_source_ips (
      account_key TEXT NOT NULL,
      source_ip TEXT NOT NULL,
      PRIMARY KEY (account_key, source_ip)
    );

    CREATE TABLE IF NOT EXISTS reports (
      account_key TEXT NOT NULL,
      report_id TEXT NOT NULL,
      org_name TEXT NOT NULL,
      domain TEXT NOT NULL,
      date_begin TEXT NOT NULL,
      date_end TEXT NOT NULL,
      total INTEGER NOT NULL,
      passing INTEGER NOT NULL,
      failing INTEGER NOT NULL,
      pass_rate REAL NOT NULL,
      policy_p TEXT,
      PRIMARY KEY (account_key, report_id)
    );

    CREATE TABLE IF NOT EXISTS report_records (
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
      PRIMARY KEY (account_key, report_id, ordinal),
      FOREIGN KEY (account_key, report_id)
        REFERENCES reports(account_key, report_id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS forensic_reports (
      account_key TEXT NOT NULL,
      id TEXT NOT NULL,
      report_id TEXT,
      org_name TEXT,
      reported_domain TEXT,
      arrival_date TEXT,
      source_ip TEXT,
      auth_failure TEXT,
      delivery_result TEXT,
      envelope_from TEXT,
      header_from TEXT,
      original_rcpt_to TEXT,
      authentication_results TEXT,
      subject TEXT,
      feedback_type TEXT,
      PRIMARY KEY (account_key, id)
    );

    CREATE TABLE IF NOT EXISTS ip_enrichment (
      ip TEXT PRIMARY KEY,
      ptr TEXT,
      provider TEXT,
      cloud_provider TEXT,
      country TEXT,
      country_code TEXT,
      city TEXT,
      asn INTEGER,
      as_org TEXT,
      dnsbl_json TEXT NOT NULL DEFAULT '[]',
      geo_source TEXT NOT NULL DEFAULT 'none',
      checked_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS dns_health_cache (
      domain TEXT PRIMARY KEY,
      result_json TEXT NOT NULL,
      checked_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    );
  `)
  db.prepare(
    `INSERT INTO schema_meta(key, value) VALUES('version', '1')
     ON CONFLICT(key) DO NOTHING`
  ).run()
  migrateSchema(db)
  migrateJsonCaches(db)
  return db
}

function schemaVersion(database: DatabaseSync): number {
  const row = database.prepare(`SELECT value FROM schema_meta WHERE key = 'version'`).get() as
    { value?: string } | undefined
  const n = Number(row?.value ?? '1')
  return Number.isFinite(n) ? n : 1
}

function setSchemaVersion(database: DatabaseSync, version: number): void {
  database
    .prepare(
      `INSERT INTO schema_meta(key, value) VALUES('version', ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value`
    )
    .run(String(version))
}

/** Incremental schema upgrades beyond the CREATE IF NOT EXISTS bootstrap. */
function migrateSchema(database: DatabaseSync): void {
  let version = schemaVersion(database)
  if (version < 2) {
    database.exec(`
      CREATE TABLE IF NOT EXISTS ip_enrichment (
        ip TEXT PRIMARY KEY,
        ptr TEXT,
        provider TEXT,
        cloud_provider TEXT,
        country TEXT,
        country_code TEXT,
        city TEXT,
        asn INTEGER,
        as_org TEXT,
        dnsbl_json TEXT NOT NULL DEFAULT '[]',
        geo_source TEXT NOT NULL DEFAULT 'none',
        checked_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS dns_health_cache (
        domain TEXT PRIMARY KEY,
        result_json TEXT NOT NULL,
        checked_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
      );
    `)
    version = 2
    setSchemaVersion(database, version)
  }
  // v3: drop enrichment rows that treated Spamhaus error codes (127.255.255.x) as hits.
  if (version < 3) {
    database.exec('DELETE FROM ip_enrichment')
    version = 3
    setSchemaVersion(database, version)
  }
  // v4: track UID watermark for optional archive mailbox.
  if (version < 4) {
    try {
      database.exec('ALTER TABLE cache_meta ADD COLUMN last_uid_archive INTEGER NOT NULL DEFAULT 0')
    } catch {
      // Column may already exist on partially migrated DBs.
    }
    version = 4
    setSchemaVersion(database, version)
  }
}

/** One-time import of legacy per-account `*.json` cache files. */
function migrateJsonCaches(database: DatabaseSync): void {
  const dir = cacheDir()
  let files: string[] = []
  try {
    files = readdirSync(dir).filter((f) => f.endsWith('.json'))
  } catch {
    return
  }
  if (files.length === 0) return

  for (const fileName of files) {
    const full = join(dir, fileName)
    try {
      withTransaction(database, () => {
        let parsed: LegacyCacheFile
        try {
          parsed = JSON.parse(readFileSync(full, 'utf8')) as LegacyCacheFile
        } catch {
          renameSync(full, `${full}.bad`)
          return
        }
        if (parsed.version !== 1 || !Array.isArray(parsed.reports)) {
          renameSync(full, `${full}.bad`)
          return
        }
        const accountKey = parsed.accountKey || fileName.replace(/\.json$/, '')
        const existing = database
          .prepare('SELECT account_key FROM cache_meta WHERE account_key = ?')
          .get(accountKey) as { account_key?: string } | undefined
        if (!existing) {
          writeAccountCache(database, {
            accountKey,
            reports: (parsed.reports ?? []).map(normalizeReport),
            forensicReports: [],
            lastUid: parsed.lastUid ?? 0,
            lastFailingTotal: parsed.lastFailingTotal ?? 0,
            knownSourceIps: parsed.knownSourceIps ?? [],
            lastFetchAt: parsed.lastFetchAt ?? null
          })
        }
        renameSync(full, `${full}.migrated`)
      })
    } catch {
      // Keep the JSON file if migration fails for this account.
    }
  }
}

function withTransaction(database: DatabaseSync, fn: () => void): void {
  database.exec('BEGIN')
  try {
    fn()
    database.exec('COMMIT')
  } catch (err) {
    try {
      database.exec('ROLLBACK')
    } catch {
      // ignore
    }
    throw err
  }
}

export function accountKeyFor(user: string, host: string, mailbox: string): string {
  const raw = `${user.trim().toLowerCase()}@${host.trim().toLowerCase()}/${mailbox.trim()}`
  return createHash('sha256').update(raw).digest('hex').slice(0, 24)
}

function emptyMeta(accountKey: string): CacheMeta {
  return {
    accountKey,
    lastUid: 0,
    lastUidArchive: 0,
    lastFetchAt: null,
    lastFailingTotal: 0,
    knownSourceIps: []
  }
}

function loadReports(database: DatabaseSync, accountKey: string): ReportRow[] {
  const reportRows = database
    .prepare(
      `SELECT report_id, org_name, domain, date_begin, date_end, total, passing, failing,
              pass_rate, policy_p
       FROM reports WHERE account_key = ?
       ORDER BY date_end DESC`
    )
    .all(accountKey) as Array<{
    report_id: string
    org_name: string
    domain: string
    date_begin: string
    date_end: string
    total: number
    passing: number
    failing: number
    pass_rate: number
    policy_p: string | null
  }>

  const recStmt = database.prepare(
    `SELECT source_ip, count, disposition, dkim_result, spf_result, header_from,
            dkim_domain, spf_domain, passes_dmarc, reasons_json, selectors_json
     FROM report_records
     WHERE account_key = ? AND report_id = ?
     ORDER BY ordinal ASC`
  )

  return reportRows.map((row) => {
    const records = (
      recStmt.all(accountKey, row.report_id) as Array<{
        source_ip: string
        count: number
        disposition: string | null
        dkim_result: string | null
        spf_result: string | null
        header_from: string | null
        dkim_domain: string | null
        spf_domain: string | null
        passes_dmarc: number
        reasons_json: string
        selectors_json: string
      }>
    ).map((rec) =>
      normalizeRecord({
        sourceIp: rec.source_ip,
        count: rec.count,
        disposition: rec.disposition,
        dkimResult: rec.dkim_result,
        spfResult: rec.spf_result,
        headerFrom: rec.header_from,
        dkimDomain: rec.dkim_domain,
        spfDomain: rec.spf_domain,
        passesDmarc: Boolean(rec.passes_dmarc),
        reasons: JSON.parse(rec.reasons_json || '[]'),
        dkimSelectors: JSON.parse(rec.selectors_json || '[]')
      })
    )
    return {
      reportId: row.report_id,
      orgName: row.org_name,
      domain: row.domain,
      dateBegin: row.date_begin,
      dateEnd: row.date_end,
      total: row.total,
      passing: row.passing,
      failing: row.failing,
      passRate: row.pass_rate,
      policyP: row.policy_p,
      records
    }
  })
}

function loadForensic(database: DatabaseSync, accountKey: string): ForensicReportRow[] {
  const rows = database
    .prepare(
      `SELECT id, report_id, org_name, reported_domain, arrival_date, source_ip, auth_failure,
              delivery_result, envelope_from, header_from, original_rcpt_to,
              authentication_results, subject, feedback_type
       FROM forensic_reports
       WHERE account_key = ?
       ORDER BY COALESCE(arrival_date, '') DESC, id DESC`
    )
    .all(accountKey) as Array<{
    id: string
    report_id: string | null
    org_name: string | null
    reported_domain: string | null
    arrival_date: string | null
    source_ip: string | null
    auth_failure: string | null
    delivery_result: string | null
    envelope_from: string | null
    header_from: string | null
    original_rcpt_to: string | null
    authentication_results: string | null
    subject: string | null
    feedback_type: string | null
  }>

  return rows.map((r) => ({
    id: r.id,
    reportId: r.report_id,
    orgName: r.org_name,
    reportedDomain: r.reported_domain,
    arrivalDate: r.arrival_date,
    sourceIp: r.source_ip,
    authFailure: r.auth_failure,
    deliveryResult: r.delivery_result,
    envelopeFrom: r.envelope_from,
    headerFrom: r.header_from,
    originalRcptTo: r.original_rcpt_to,
    authenticationResults: r.authentication_results,
    subject: r.subject,
    feedbackType: r.feedback_type
  }))
}

function writeAccountCache(
  database: DatabaseSync,
  input: {
    accountKey: string
    reports: ReportRow[]
    forensicReports: ForensicReportRow[]
    lastUid: number
    lastUidArchive?: number
    lastFailingTotal: number
    knownSourceIps: string[]
    lastFetchAt: string | null
  }
): void {
  database.prepare('DELETE FROM report_records WHERE account_key = ?').run(input.accountKey)
  database.prepare('DELETE FROM reports WHERE account_key = ?').run(input.accountKey)
  database.prepare('DELETE FROM forensic_reports WHERE account_key = ?').run(input.accountKey)
  database.prepare('DELETE FROM known_source_ips WHERE account_key = ?').run(input.accountKey)
  database.prepare('DELETE FROM cache_meta WHERE account_key = ?').run(input.accountKey)

  database
    .prepare(
      `INSERT INTO cache_meta(account_key, last_uid, last_uid_archive, last_fetch_at, last_failing_total)
       VALUES (?, ?, ?, ?, ?)`
    )
    .run(
      input.accountKey,
      input.lastUid,
      input.lastUidArchive ?? 0,
      input.lastFetchAt,
      input.lastFailingTotal
    )

  const ipStmt = database.prepare(
    'INSERT INTO known_source_ips(account_key, source_ip) VALUES (?, ?)'
  )
  for (const ip of input.knownSourceIps) {
    ipStmt.run(input.accountKey, ip)
  }

  const reportStmt = database.prepare(
    `INSERT INTO reports(
       account_key, report_id, org_name, domain, date_begin, date_end,
       total, passing, failing, pass_rate, policy_p
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
  const recStmt = database.prepare(
    `INSERT INTO report_records(
       account_key, report_id, ordinal, source_ip, count, disposition, dkim_result, spf_result,
       header_from, dkim_domain, spf_domain, passes_dmarc, reasons_json, selectors_json
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )

  for (const report of input.reports) {
    const reportId =
      report.reportId || `${report.orgName}|${report.domain}|${report.dateBegin}|${report.dateEnd}`
    reportStmt.run(
      input.accountKey,
      reportId,
      report.orgName,
      report.domain,
      report.dateBegin,
      report.dateEnd,
      report.total,
      report.passing,
      report.failing,
      report.passRate,
      report.policyP
    )
    report.records.forEach((rec, ordinal) => {
      recStmt.run(
        input.accountKey,
        reportId,
        ordinal,
        rec.sourceIp,
        rec.count,
        rec.disposition,
        rec.dkimResult,
        rec.spfResult,
        rec.headerFrom,
        rec.dkimDomain,
        rec.spfDomain,
        rec.passesDmarc ? 1 : 0,
        JSON.stringify(rec.reasons ?? []),
        JSON.stringify(rec.dkimSelectors ?? [])
      )
    })
  }

  const forensicStmt = database.prepare(
    `INSERT INTO forensic_reports(
       account_key, id, report_id, org_name, reported_domain, arrival_date, source_ip,
       auth_failure, delivery_result, envelope_from, header_from, original_rcpt_to,
       authentication_results, subject, feedback_type
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
  for (const f of input.forensicReports) {
    forensicStmt.run(
      input.accountKey,
      f.id,
      f.reportId,
      f.orgName,
      f.reportedDomain,
      f.arrivalDate,
      f.sourceIp,
      f.authFailure,
      f.deliveryResult,
      f.envelopeFrom,
      f.headerFrom,
      f.originalRcptTo,
      f.authenticationResults,
      f.subject,
      f.feedbackType
    )
  }
}

export function loadCachedReports(accountKey: string): {
  reports: ReportRow[]
  forensicReports: ForensicReportRow[]
  meta: CacheMeta
} {
  const database = openDb()
  const metaRow = database
    .prepare(
      `SELECT last_uid, last_uid_archive, last_fetch_at, last_failing_total
       FROM cache_meta WHERE account_key = ?`
    )
    .get(accountKey) as
    | {
        last_uid: number
        last_uid_archive: number | null
        last_fetch_at: string | null
        last_failing_total: number
      }
    | undefined

  if (!metaRow) {
    return { reports: [], forensicReports: [], meta: emptyMeta(accountKey) }
  }

  const ips = (
    database
      .prepare('SELECT source_ip FROM known_source_ips WHERE account_key = ? ORDER BY source_ip')
      .all(accountKey) as Array<{ source_ip: string }>
  ).map((r) => r.source_ip)

  return {
    reports: loadReports(database, accountKey),
    forensicReports: loadForensic(database, accountKey),
    meta: {
      accountKey,
      lastUid: metaRow.last_uid,
      lastUidArchive: metaRow.last_uid_archive ?? 0,
      lastFetchAt: metaRow.last_fetch_at,
      lastFailingTotal: metaRow.last_failing_total,
      knownSourceIps: ips
    }
  }
}

export function mergeReports(existing: ReportRow[], incoming: ReportRow[]): ReportRow[] {
  const map = new Map<string, ReportRow>()
  for (const r of existing) {
    if (r.reportId) map.set(r.reportId, r)
  }
  for (const r of incoming) {
    if (r.reportId) map.set(r.reportId, r)
    else map.set(`${r.orgName}|${r.domain}|${r.dateBegin}|${r.dateEnd}`, r)
  }
  return [...map.values()].sort((a, b) => b.dateEnd.localeCompare(a.dateEnd))
}

export function mergeForensicReports(
  existing: ForensicReportRow[],
  incoming: ForensicReportRow[]
): ForensicReportRow[] {
  const map = new Map<string, ForensicReportRow>()
  for (const r of existing) map.set(r.id, r)
  for (const r of incoming) map.set(r.id, r)
  return [...map.values()].sort((a, b) => (b.arrivalDate ?? '').localeCompare(a.arrivalDate ?? ''))
}

export function saveCache(input: {
  accountKey: string
  reports: ReportRow[]
  forensicReports?: ForensicReportRow[]
  lastUid: number
  lastUidArchive?: number
  lastFailingTotal: number
  knownSourceIps: string[]
}): CacheMeta {
  const database = openDb()
  const lastFetchAt = new Date().toISOString()
  const forensicReports = input.forensicReports ?? []
  const lastUidArchive = input.lastUidArchive ?? 0
  withTransaction(database, () => {
    writeAccountCache(database, {
      accountKey: input.accountKey,
      reports: input.reports.map(normalizeReport),
      forensicReports,
      lastUid: input.lastUid,
      lastUidArchive,
      lastFailingTotal: input.lastFailingTotal,
      knownSourceIps: input.knownSourceIps,
      lastFetchAt
    })
  })
  return {
    accountKey: input.accountKey,
    lastUid: input.lastUid,
    lastUidArchive,
    lastFetchAt,
    lastFailingTotal: input.lastFailingTotal,
    knownSourceIps: input.knownSourceIps
  }
}

export function clearCache(accountKey: string): void {
  const database = openDb()
  withTransaction(database, () => {
    writeAccountCache(database, {
      accountKey,
      reports: [],
      forensicReports: [],
      lastUid: 0,
      lastUidArchive: 0,
      lastFailingTotal: 0,
      knownSourceIps: [],
      lastFetchAt: null
    })
  })
}

const IP_ENRICHMENT_TTL_MS = 7 * 24 * 60 * 60 * 1000
const DNS_HEALTH_TTL_MS = 6 * 60 * 60 * 1000

function rowToIpInfo(row: {
  ip: string
  ptr: string | null
  provider: string | null
  cloud_provider: string | null
  country: string | null
  country_code: string | null
  city: string | null
  asn: number | null
  as_org: string | null
  dnsbl_json: string
  geo_source: string
}): IpInfo {
  let dnsblHits: string[] = []
  try {
    dnsblHits = JSON.parse(row.dnsbl_json || '[]') as string[]
  } catch {
    dnsblHits = []
  }
  const geoSource =
    row.geo_source === 'maxmind' || row.geo_source === 'online' ? row.geo_source : 'none'
  return {
    ip: row.ip,
    ptr: row.ptr,
    provider: row.provider,
    country: row.country,
    countryCode: row.country_code,
    city: row.city,
    asn: row.asn,
    asOrg: row.as_org,
    cloudProvider: row.cloud_provider,
    dnsblHits,
    geoSource
  }
}

/** Return non-expired enrichment rows for the given IPs. */
export function getIpEnrichment(ips: string[]): Map<string, IpInfo> {
  const database = openDb()
  const now = new Date().toISOString()
  const out = new Map<string, IpInfo>()
  const stmt = database.prepare(
    `SELECT ip, ptr, provider, cloud_provider, country, country_code, city, asn, as_org,
            dnsbl_json, geo_source
     FROM ip_enrichment
     WHERE ip = ? AND expires_at > ?`
  )
  for (const ip of ips) {
    const row = stmt.get(ip, now) as
      | {
          ip: string
          ptr: string | null
          provider: string | null
          cloud_provider: string | null
          country: string | null
          country_code: string | null
          city: string | null
          asn: number | null
          as_org: string | null
          dnsbl_json: string
          geo_source: string
        }
      | undefined
    if (row) out.set(ip, rowToIpInfo(row))
  }
  return out
}

export function upsertIpEnrichment(infos: IpInfo[], ttlMs = IP_ENRICHMENT_TTL_MS): void {
  if (infos.length === 0) return
  const database = openDb()
  const checkedAt = new Date().toISOString()
  const expiresAt = new Date(Date.now() + ttlMs).toISOString()
  const stmt = database.prepare(
    `INSERT INTO ip_enrichment(
       ip, ptr, provider, cloud_provider, country, country_code, city, asn, as_org,
       dnsbl_json, geo_source, checked_at, expires_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(ip) DO UPDATE SET
       ptr = excluded.ptr,
       provider = excluded.provider,
       cloud_provider = excluded.cloud_provider,
       country = excluded.country,
       country_code = excluded.country_code,
       city = excluded.city,
       asn = excluded.asn,
       as_org = excluded.as_org,
       dnsbl_json = excluded.dnsbl_json,
       geo_source = excluded.geo_source,
       checked_at = excluded.checked_at,
       expires_at = excluded.expires_at`
  )
  withTransaction(database, () => {
    for (const info of infos) {
      stmt.run(
        info.ip,
        info.ptr,
        info.provider,
        info.cloudProvider,
        info.country,
        info.countryCode,
        info.city,
        info.asn,
        info.asOrg,
        JSON.stringify(info.dnsblHits ?? []),
        info.geoSource,
        checkedAt,
        expiresAt
      )
    }
  })
}

export function getDnsHealthCache(domain: string): DnsCheckResult | null {
  const database = openDb()
  const now = new Date().toISOString()
  const row = database
    .prepare(`SELECT result_json FROM dns_health_cache WHERE domain = ? AND expires_at > ?`)
    .get(domain.trim().toLowerCase(), now) as { result_json?: string } | undefined
  if (!row?.result_json) return null
  try {
    return JSON.parse(row.result_json) as DnsCheckResult
  } catch {
    return null
  }
}

export function upsertDnsHealthCache(
  domain: string,
  result: DnsCheckResult,
  ttlMs = DNS_HEALTH_TTL_MS
): void {
  const database = openDb()
  const checkedAt = new Date().toISOString()
  const expiresAt = new Date(Date.now() + ttlMs).toISOString()
  database
    .prepare(
      `INSERT INTO dns_health_cache(domain, result_json, checked_at, expires_at)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(domain) DO UPDATE SET
         result_json = excluded.result_json,
         checked_at = excluded.checked_at,
         expires_at = excluded.expires_at`
    )
    .run(domain.trim().toLowerCase(), JSON.stringify(result), checkedAt, expiresAt)
}

/** Close the DB (tests / shutdown). */
export function closeCacheDb(): void {
  if (db) {
    try {
      db.close()
    } catch {
      // ignore
    }
    db = null
  }
}
