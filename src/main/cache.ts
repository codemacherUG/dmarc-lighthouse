import { app } from 'electron'
import { createHash, randomUUID } from 'crypto'
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync } from 'fs'
import { join } from 'path'
import { DatabaseSync } from 'node:sqlite'
import type {
  DnsDriftEvent,
  DnsDriftKind,
  DnsCheckResult,
  DnsHistoryResult,
  DnsHistorySnapshot,
  DnsHistorySnapshotKind,
  DnsReportCorrelation,
  ForensicReportRow,
  IpInfo,
  ReportRow,
  SenderKind,
  SendingService,
  SendingServiceInput,
  SerializedRecord,
  TransportSecurityResult
} from '../shared/types'

export interface CacheMeta {
  accountKey: string
  lastUid: number
  /** UID watermark for the optional archive mailbox (when dual-folder fetch is used). */
  lastUidArchive: number
  lastFetchAt: string | null
  lastFailingTotal: number
  knownSourceIps: string[]
  /** Newly discovered source IPs that have not been dismissed or accepted yet. */
  pendingSourceIps: string[]
  /** Set by `resetKnownSourceIps`; the next fetch treats every current sender as new once. */
  knownIpsResetPending: boolean
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
  const dir = cacheDir()
  const next = join(dir, 'dmarc-lighthouse.sqlite')
  const legacy = join(dir, 'dmarcviewer.sqlite')
  if (!existsSync(next) && existsSync(legacy)) {
    renameSync(legacy, next)
  }
  return next
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

    CREATE TABLE IF NOT EXISTS pending_source_ips (
      account_key TEXT NOT NULL,
      source_ip TEXT NOT NULL,
      discovered_at TEXT NOT NULL,
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
      sender_kind TEXT,
      cloud_provider TEXT,
      country TEXT,
      country_code TEXT,
      city TEXT,
      lat REAL,
      lon REAL,
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

    CREATE TABLE IF NOT EXISTS dns_history_snapshots (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      domain TEXT NOT NULL,
      kind TEXT NOT NULL,
      checked_at TEXT NOT NULL,
      fingerprint TEXT NOT NULL,
      result_json TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS dns_history_snapshots_domain_idx
      ON dns_history_snapshots(domain, kind, checked_at DESC, id DESC);

    CREATE TABLE IF NOT EXISTS dns_drift_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      domain TEXT NOT NULL,
      snapshot_id INTEGER NOT NULL,
      kind TEXT NOT NULL,
      checked_at TEXT NOT NULL,
      title TEXT NOT NULL,
      detail TEXT NOT NULL,
      before_value TEXT,
      after_value TEXT,
      selector TEXT,
      FOREIGN KEY (snapshot_id) REFERENCES dns_history_snapshots(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS dns_drift_events_domain_idx
      ON dns_drift_events(domain, checked_at DESC, id DESC);

    CREATE TABLE IF NOT EXISTS sending_services (
      id TEXT PRIMARY KEY,
      provider TEXT NOT NULL,
      domain TEXT,
      cidr TEXT,
      asn INTEGER,
      status TEXT NOT NULL,
      note TEXT,
      team TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
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
        lat REAL,
        lon REAL,
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
  // v5: store map coordinates from GeoIP for OSM markers.
  if (version < 5) {
    try {
      database.exec('ALTER TABLE ip_enrichment ADD COLUMN lat REAL')
    } catch {
      // Column may already exist.
    }
    try {
      database.exec('ALTER TABLE ip_enrichment ADD COLUMN lon REAL')
    } catch {
      // Column may already exist.
    }
    database.exec('DELETE FROM ip_enrichment')
    version = 5
    setSchemaVersion(database, version)
  }
  // v6: identify the sending service, so `provider` now means e.g. "Amazon SES".
  if (version < 6) {
    try {
      database.exec('ALTER TABLE ip_enrichment ADD COLUMN sender_kind TEXT')
    } catch {
      // Column may already exist.
    }
    database.exec('DELETE FROM ip_enrichment')
    version = 6
    setSchemaVersion(database, version)
  }
  // v7: permanent DNS/transport snapshots and drift events. This is not cleared with caches.
  if (version < 7) {
    database.exec(`
      CREATE TABLE IF NOT EXISTS dns_history_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        kind TEXT NOT NULL,
        checked_at TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        result_json TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS dns_history_snapshots_domain_idx
        ON dns_history_snapshots(domain, kind, checked_at DESC, id DESC);

      CREATE TABLE IF NOT EXISTS dns_drift_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        snapshot_id INTEGER NOT NULL,
        kind TEXT NOT NULL,
        checked_at TEXT NOT NULL,
        title TEXT NOT NULL,
        detail TEXT NOT NULL,
        before_value TEXT,
        after_value TEXT,
        selector TEXT,
        FOREIGN KEY (snapshot_id) REFERENCES dns_history_snapshots(id) ON DELETE CASCADE
      );

      CREATE INDEX IF NOT EXISTS dns_drift_events_domain_idx
        ON dns_drift_events(domain, checked_at DESC, id DESC);
    `)
    version = 7
    setSchemaVersion(database, version)
  }
  // v8: persistent sending-service inventory (known/unknown/retired/investigate).
  if (version < 8) {
    database.exec(`
      CREATE TABLE IF NOT EXISTS sending_services (
        id TEXT PRIMARY KEY,
        provider TEXT NOT NULL,
        domain TEXT,
        cidr TEXT,
        asn INTEGER,
        status TEXT NOT NULL,
        note TEXT,
        team TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
    `)
    version = 8
    setSchemaVersion(database, version)
  }
  // v9: explicit "reset known sources" so the reset request survives until the next fetch.
  if (version < 9) {
    try {
      database.exec(
        'ALTER TABLE cache_meta ADD COLUMN known_ips_reset_pending INTEGER NOT NULL DEFAULT 0'
      )
    } catch {
      // Column may already exist on partially migrated DBs.
    }
    version = 9
    setSchemaVersion(database, version)
  }
  // v10: keep unresolved new-source alerts across app restarts.
  if (version < 10) {
    database.exec(`
      CREATE TABLE IF NOT EXISTS pending_source_ips (
        account_key TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        discovered_at TEXT NOT NULL,
        PRIMARY KEY (account_key, source_ip)
      );
    `)
    version = 10
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

/** Cache slot for local file imports while no IMAP account is configured. */
export const LOCAL_IMPORT_ACCOUNT_KEY = 'local-import'

/** Primary key for a report; falls back to org/domain/window for reports without an ID. */
function reportKeyFor(report: ReportRow): string {
  return (
    report.reportId || `${report.orgName}|${report.domain}|${report.dateBegin}|${report.dateEnd}`
  )
}

function emptyMeta(accountKey: string): CacheMeta {
  return {
    accountKey,
    lastUid: 0,
    lastUidArchive: 0,
    lastFetchAt: null,
    lastFailingTotal: 0,
    knownSourceIps: [],
    pendingSourceIps: [],
    knownIpsResetPending: false
  }
}

function recordFromRow(rec: {
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
}): SerializedRecord {
  return normalizeRecord({
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

  if (reportRows.length === 0) return []

  const recRows = database
    .prepare(
      `SELECT report_id, source_ip, count, disposition, dkim_result, spf_result, header_from,
              dkim_domain, spf_domain, passes_dmarc, reasons_json, selectors_json
       FROM report_records
       WHERE account_key = ?
       ORDER BY report_id, ordinal ASC`
    )
    .all(accountKey) as Array<{
    report_id: string
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

  const recordsByReport = new Map<string, SerializedRecord[]>()
  for (const rec of recRows) {
    const item = recordFromRow(rec)
    const list = recordsByReport.get(rec.report_id)
    if (list) list.push(item)
    else recordsByReport.set(rec.report_id, [item])
  }

  return reportRows.map((row) => ({
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
    records: recordsByReport.get(row.report_id) ?? []
  }))
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
  database.prepare('DELETE FROM pending_source_ips WHERE account_key = ?').run(input.accountKey)
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
    const reportId = reportKeyFor(report)
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
      `SELECT last_uid, last_uid_archive, last_fetch_at, last_failing_total, known_ips_reset_pending
       FROM cache_meta WHERE account_key = ?`
    )
    .get(accountKey) as
    | {
        last_uid: number
        last_uid_archive: number | null
        last_fetch_at: string | null
        last_failing_total: number
        known_ips_reset_pending: number | null
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
  const pendingIps = (
    database
      .prepare(
        'SELECT source_ip FROM pending_source_ips WHERE account_key = ? ORDER BY discovered_at, source_ip'
      )
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
      knownSourceIps: ips,
      pendingSourceIps: pendingIps,
      knownIpsResetPending: Boolean(metaRow.known_ips_reset_pending)
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

export interface ImportCacheResult {
  addedReports: number
  updatedReports: number
  addedForensic: number
}

function upsertKnownIps(database: DatabaseSync, accountKey: string, ips: Iterable<string>): void {
  const ipStmt = database.prepare(
    `INSERT INTO known_source_ips(account_key, source_ip) VALUES (?, ?)
     ON CONFLICT(account_key, source_ip) DO NOTHING`
  )
  for (const ip of ips) {
    if (ip) ipStmt.run(accountKey, ip)
  }
}

function upsertAccountReports(
  database: DatabaseSync,
  accountKey: string,
  reports: ReportRow[],
  forensicReports: ForensicReportRow[]
): ImportCacheResult {
  const result: ImportCacheResult = { addedReports: 0, updatedReports: 0, addedForensic: 0 }
  const reportExists = database.prepare(
    'SELECT 1 AS hit FROM reports WHERE account_key = ? AND report_id = ?'
  )
  const upsertReport = database.prepare(
    `INSERT INTO reports(
       account_key, report_id, org_name, domain, date_begin, date_end,
       total, passing, failing, pass_rate, policy_p
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(account_key, report_id) DO UPDATE SET
       org_name = excluded.org_name,
       domain = excluded.domain,
       date_begin = excluded.date_begin,
       date_end = excluded.date_end,
       total = excluded.total,
       passing = excluded.passing,
       failing = excluded.failing,
       pass_rate = excluded.pass_rate,
       policy_p = excluded.policy_p`
  )
  const clearRecords = database.prepare(
    'DELETE FROM report_records WHERE account_key = ? AND report_id = ?'
  )
  const recStmt = database.prepare(
    `INSERT INTO report_records(
       account_key, report_id, ordinal, source_ip, count, disposition, dkim_result, spf_result,
       header_from, dkim_domain, spf_domain, passes_dmarc, reasons_json, selectors_json
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
  const ipStmt = database.prepare(
    `INSERT INTO known_source_ips(account_key, source_ip) VALUES (?, ?)
     ON CONFLICT(account_key, source_ip) DO NOTHING`
  )

  for (const report of reports) {
    const reportId = reportKeyFor(report)
    const seen = reportExists.get(accountKey, reportId) as { hit?: number } | undefined
    if (seen) result.updatedReports += 1
    else result.addedReports += 1

    upsertReport.run(
      accountKey,
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
    clearRecords.run(accountKey, reportId)
    report.records.forEach((rec, ordinal) => {
      recStmt.run(
        accountKey,
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
      if (rec.sourceIp) ipStmt.run(accountKey, rec.sourceIp)
    })
  }

  const forensicExists = database.prepare(
    'SELECT 1 AS hit FROM forensic_reports WHERE account_key = ? AND id = ?'
  )
  const upsertForensic = database.prepare(
    `INSERT INTO forensic_reports(
       account_key, id, report_id, org_name, reported_domain, arrival_date, source_ip,
       auth_failure, delivery_result, envelope_from, header_from, original_rcpt_to,
       authentication_results, subject, feedback_type
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(account_key, id) DO UPDATE SET
       report_id = excluded.report_id,
       org_name = excluded.org_name,
       reported_domain = excluded.reported_domain,
       arrival_date = excluded.arrival_date,
       source_ip = excluded.source_ip,
       auth_failure = excluded.auth_failure,
       delivery_result = excluded.delivery_result,
       envelope_from = excluded.envelope_from,
       header_from = excluded.header_from,
       original_rcpt_to = excluded.original_rcpt_to,
       authentication_results = excluded.authentication_results,
       subject = excluded.subject,
       feedback_type = excluded.feedback_type`
  )
  for (const f of forensicReports) {
    const seen = forensicExists.get(accountKey, f.id) as { hit?: number } | undefined
    if (!seen) result.addedForensic += 1
    upsertForensic.run(
      accountKey,
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
    if (f.sourceIp) ipStmt.run(accountKey, f.sourceIp)
  }

  return result
}

/**
 * Upsert reports into the account cache and refresh IMAP watermarks.
 *
 * Existing reports that are not in `input.reports` stay in place — callers
 * should pass only newly fetched rows, not the merged history.
 */
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
  const reports = input.reports.map(normalizeReport)
  withTransaction(database, () => {
    database
      .prepare(
        `INSERT INTO cache_meta(account_key, last_uid, last_uid_archive, last_fetch_at, last_failing_total)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(account_key) DO UPDATE SET
           last_uid = excluded.last_uid,
           last_uid_archive = excluded.last_uid_archive,
           last_fetch_at = excluded.last_fetch_at,
           last_failing_total = excluded.last_failing_total`
      )
      .run(input.accountKey, input.lastUid, lastUidArchive, lastFetchAt, input.lastFailingTotal)
    upsertAccountReports(database, input.accountKey, reports, forensicReports)
    upsertKnownIps(database, input.accountKey, input.knownSourceIps)
  })
  return {
    accountKey: input.accountKey,
    lastUid: input.lastUid,
    lastUidArchive,
    lastFetchAt,
    lastFailingTotal: input.lastFailingTotal,
    knownSourceIps: input.knownSourceIps,
    pendingSourceIps: [],
    knownIpsResetPending: false
  }
}

/** Adds newly discovered source IPs to the durable review queue. */
export function addPendingSourceIps(accountKey: string, ips: Iterable<string>): void {
  const database = openDb()
  const statement = database.prepare(
    `INSERT INTO pending_source_ips(account_key, source_ip, discovered_at) VALUES (?, ?, ?)
     ON CONFLICT(account_key, source_ip) DO NOTHING`
  )
  const discoveredAt = new Date().toISOString()
  withTransaction(database, () => {
    for (const ip of ips) {
      if (ip) statement.run(accountKey, ip, discoveredAt)
    }
  })
}

/** Removes selected pending sources, or the complete review queue when no IPs are supplied. */
export function acknowledgePendingSourceIps(accountKey: string, ips?: Iterable<string>): void {
  const database = openDb()
  if (ips == null) {
    database.prepare('DELETE FROM pending_source_ips WHERE account_key = ?').run(accountKey)
    return
  }
  const statement = database.prepare(
    'DELETE FROM pending_source_ips WHERE account_key = ? AND source_ip = ?'
  )
  withTransaction(database, () => {
    for (const ip of ips) statement.run(accountKey, ip)
  })
}

/** Clears the "seen" IP baseline so the next fetch treats every current sender as new once. */
export function resetKnownSourceIps(accountKey: string): void {
  const database = openDb()
  withTransaction(database, () => {
    database.prepare('DELETE FROM known_source_ips WHERE account_key = ?').run(accountKey)
    database
      .prepare(
        `INSERT INTO cache_meta(account_key, last_uid, last_uid_archive, last_fetch_at, last_failing_total, known_ips_reset_pending)
         VALUES (?, 0, 0, NULL, 0, 1)
         ON CONFLICT(account_key) DO UPDATE SET known_ips_reset_pending = 1`
      )
      .run(accountKey)
  })
}

/** Clears the pending reset flag without touching the known-IP set (normal fetch already saved it). */
export function clearKnownIpsResetPending(accountKey: string): void {
  const database = openDb()
  database
    .prepare('UPDATE cache_meta SET known_ips_reset_pending = 0 WHERE account_key = ?')
    .run(accountKey)
}

/** Re-seeds the known-IP set and clears the pending flag in one go (no-new-mail fetch path). */
export function reseedKnownIps(accountKey: string, ips: Iterable<string>): void {
  const database = openDb()
  withTransaction(database, () => {
    upsertKnownIps(database, accountKey, ips)
    database
      .prepare('UPDATE cache_meta SET known_ips_reset_pending = 0 WHERE account_key = ?')
      .run(accountKey)
  })
}

/**
 * Upsert locally imported reports into an account's cache.
 *
 * Unlike `saveCache` this touches neither the UID watermarks nor `last_fetch_at`,
 * so importing files can never make the next IMAP fetch skip messages. The
 * failing baseline is recomputed so imported failures do not trigger alerts.
 */
export function importReports(input: {
  accountKey: string
  reports: ReportRow[]
  forensicReports?: ForensicReportRow[]
}): ImportCacheResult {
  const database = openDb()
  const { accountKey } = input
  const reports = input.reports.map(normalizeReport)
  const forensicReports = input.forensicReports ?? []
  const result: ImportCacheResult = { addedReports: 0, updatedReports: 0, addedForensic: 0 }
  if (reports.length === 0 && forensicReports.length === 0) return result

  withTransaction(database, () => {
    database
      .prepare(
        `INSERT INTO cache_meta(account_key, last_uid, last_uid_archive, last_fetch_at, last_failing_total)
         VALUES (?, 0, 0, NULL, 0)
         ON CONFLICT(account_key) DO NOTHING`
      )
      .run(accountKey)

    const stored = upsertAccountReports(database, accountKey, reports, forensicReports)
    result.addedReports = stored.addedReports
    result.updatedReports = stored.updatedReports
    result.addedForensic = stored.addedForensic

    database
      .prepare(
        `UPDATE cache_meta
         SET last_failing_total = (
           SELECT COALESCE(SUM(failing), 0) FROM reports WHERE account_key = ?
         )
         WHERE account_key = ?`
      )
      .run(accountKey, accountKey)
  })

  return result
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

function rowToSendingService(row: {
  id: string
  provider: string
  domain: string | null
  cidr: string | null
  asn: number | null
  status: string
  note: string | null
  team: string | null
  created_at: string
  updated_at: string
}): SendingService {
  return {
    id: row.id,
    provider: row.provider,
    domain: row.domain,
    cidr: row.cidr,
    asn: row.asn,
    status: row.status as SendingService['status'],
    note: row.note,
    team: row.team,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  }
}

export function listSendingServices(): SendingService[] {
  const database = openDb()
  const rows = database
    .prepare(
      `SELECT id, provider, domain, cidr, asn, status, note, team, created_at, updated_at
       FROM sending_services
       ORDER BY provider COLLATE NOCASE, domain COLLATE NOCASE`
    )
    .all() as Array<{
    id: string
    provider: string
    domain: string | null
    cidr: string | null
    asn: number | null
    status: string
    note: string | null
    team: string | null
    created_at: string
    updated_at: string
  }>
  return rows.map(rowToSendingService)
}

export function upsertSendingService(input: SendingServiceInput): SendingService {
  const database = openDb()
  const now = new Date().toISOString()
  const id = input.id && input.id.trim() ? input.id : randomUUID()
  const existing = database
    .prepare('SELECT created_at FROM sending_services WHERE id = ?')
    .get(id) as { created_at: string } | undefined
  const createdAt = existing?.created_at ?? now
  database
    .prepare(
      `INSERT INTO sending_services(
         id, provider, domain, cidr, asn, status, note, team, created_at, updated_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         provider = excluded.provider,
         domain = excluded.domain,
         cidr = excluded.cidr,
         asn = excluded.asn,
         status = excluded.status,
         note = excluded.note,
         team = excluded.team,
         updated_at = excluded.updated_at`
    )
    .run(
      id,
      input.provider,
      input.domain,
      input.cidr,
      input.asn,
      input.status,
      input.note,
      input.team,
      createdAt,
      now
    )
  return {
    id,
    provider: input.provider,
    domain: input.domain,
    cidr: input.cidr,
    asn: input.asn,
    status: input.status,
    note: input.note,
    team: input.team,
    createdAt,
    updatedAt: now
  }
}

export function deleteSendingService(id: string): void {
  const database = openDb()
  database.prepare('DELETE FROM sending_services WHERE id = ?').run(id)
}

const SENDER_KINDS = new Set<SenderKind>(['esp', 'mailbox', 'saas', 'gateway', 'infra'])

function toSenderKind(value: string | null): SenderKind | null {
  return value && SENDER_KINDS.has(value as SenderKind) ? (value as SenderKind) : null
}

function rowToIpInfo(row: {
  ip: string
  ptr: string | null
  provider: string | null
  sender_kind: string | null
  cloud_provider: string | null
  country: string | null
  country_code: string | null
  city: string | null
  lat: number | null
  lon: number | null
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
    senderKind: toSenderKind(row.sender_kind),
    country: row.country,
    countryCode: row.country_code,
    city: row.city,
    lat: typeof row.lat === 'number' && Number.isFinite(row.lat) ? row.lat : null,
    lon: typeof row.lon === 'number' && Number.isFinite(row.lon) ? row.lon : null,
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
    `SELECT ip, ptr, provider, sender_kind, cloud_provider, country, country_code, city, lat, lon,
            asn, as_org, dnsbl_json, geo_source
     FROM ip_enrichment
     WHERE ip = ? AND expires_at > ?`
  )
  for (const ip of ips) {
    const row = stmt.get(ip, now) as
      | {
          ip: string
          ptr: string | null
          provider: string | null
          sender_kind: string | null
          cloud_provider: string | null
          country: string | null
          country_code: string | null
          city: string | null
          lat: number | null
          lon: number | null
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
       ip, ptr, provider, sender_kind, cloud_provider, country, country_code, city, lat, lon, asn,
       as_org, dnsbl_json, geo_source, checked_at, expires_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(ip) DO UPDATE SET
       ptr = excluded.ptr,
       provider = excluded.provider,
       sender_kind = excluded.sender_kind,
       cloud_provider = excluded.cloud_provider,
       country = excluded.country,
       country_code = excluded.country_code,
       city = excluded.city,
       lat = excluded.lat,
       lon = excluded.lon,
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
        info.senderKind,
        info.cloudProvider,
        info.country,
        info.countryCode,
        info.city,
        info.lat,
        info.lon,
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

type HistoryResult = DnsCheckResult | TransportSecurityResult

interface PendingDrift {
  kind: DnsDriftKind
  checkedAt: string
  title: string
  detail: string
  before: string | null
  after: string | null
  selector?: string
}

function domainKey(domain: string): string {
  return domain.trim().toLowerCase().replace(/\.$/, '')
}

function sortedStrings(values: string[] | undefined): string[] {
  return [...new Set((values ?? []).map((v) => v.trim()).filter(Boolean))].sort()
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`
  if (value && typeof value === 'object') {
    const object = value as Record<string, unknown>
    return `{${Object.keys(object)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableJson(object[key])}`)
      .join(',')}}`
  }
  return JSON.stringify(value)
}

function snapshotFingerprint(kind: DnsHistorySnapshotKind, result: HistoryResult): string {
  return createHash('sha256')
    .update(stableJson(canonicalHistoryResult(kind, result)))
    .digest('hex')
}

function canonicalHistoryResult(kind: DnsHistorySnapshotKind, result: HistoryResult): unknown {
  if (kind === 'transport') {
    const transport = result as TransportSecurityResult
    return {
      tlsrpt: {
        records: sortedStrings(transport.tlsrpt.records),
        rua: sortedStrings(transport.tlsrpt.rua)
      },
      mtaSts: {
        records: sortedStrings(transport.mtaSts.records),
        id: transport.mtaSts.id,
        policy: transport.mtaSts.policy
          ? {
              ...transport.mtaSts.policy,
              mx: sortedStrings(transport.mtaSts.policy.mx)
            }
          : null
      }
    }
  }

  const dns = result as DnsCheckResult
  return {
    dmarc: { host: dns.dmarc.host ?? null, records: sortedStrings(dns.dmarc.records) },
    spf: sortedStrings(dns.spf.records),
    dkim: dns.dkim.selectors
      .map((s) => ({ selector: s.selector, record: s.record ?? null }))
      .sort((a, b) => a.selector.localeCompare(b.selector)),
    bimi: dns.bimi ? { host: dns.bimi.host, records: sortedStrings(dns.bimi.records) } : null
  }
}

function lines(values: string[]): string | null {
  return values.length > 0 ? values.join('\n') : null
}

function spfIncludes(records: string[]): string[] {
  const includes = new Set<string>()
  for (const record of records) {
    for (const match of record.matchAll(/(?:^|\s)include:([^\s]+)/gi)) {
      if (match[1]) includes.add(match[1].toLowerCase())
    }
  }
  return [...includes].sort()
}

function dkimRecordsBySelector(result: DnsCheckResult): Map<string, string> {
  const out = new Map<string, string>()
  for (const item of result.dkim.selectors) {
    if (item.record) out.set(item.selector, item.record.trim())
  }
  return out
}

function pushDrift(
  events: PendingDrift[],
  input: Omit<PendingDrift, 'checkedAt'>,
  checkedAt: string
): void {
  events.push({ ...input, checkedAt })
}

function detectDnsDrifts(before: DnsCheckResult, after: DnsCheckResult): PendingDrift[] {
  const events: PendingDrift[] = []
  const checkedAt = after.checkedAt
  const beforeDmarc = lines(sortedStrings(before.dmarc.records))
  const afterDmarc = lines(sortedStrings(after.dmarc.records))
  if (beforeDmarc !== afterDmarc) {
    pushDrift(
      events,
      {
        kind: 'dmarc-changed',
        title: 'DMARC geändert',
        detail: 'Der DMARC-TXT-Record hat sich seit dem letzten Check verändert.',
        before: beforeDmarc,
        after: afterDmarc
      },
      checkedAt
    )
  }

  const beforeSpf = lines(sortedStrings(before.spf.records))
  const afterSpf = lines(sortedStrings(after.spf.records))
  if (beforeSpf !== afterSpf) {
    const removedIncludes = spfIncludes(before.spf.records).filter(
      (include) => !spfIncludes(after.spf.records).includes(include)
    )
    if (removedIncludes.length > 0) {
      pushDrift(
        events,
        {
          kind: 'spf-include-removed',
          title: 'SPF include entfernt',
          detail: `Entfernt: ${removedIncludes.join(', ')}`,
          before: beforeSpf,
          after: afterSpf
        },
        checkedAt
      )
    } else {
      pushDrift(
        events,
        {
          kind: 'spf-changed',
          title: 'SPF geändert',
          detail: 'Der SPF-TXT-Record hat sich seit dem letzten Check verändert.',
          before: beforeSpf,
          after: afterSpf
        },
        checkedAt
      )
    }
  }

  const beforeDkim = dkimRecordsBySelector(before)
  const afterDkim = dkimRecordsBySelector(after)
  const selectors = [...new Set([...beforeDkim.keys(), ...afterDkim.keys()])].sort()
  for (const selector of selectors) {
    const oldRecord = beforeDkim.get(selector) ?? null
    const newRecord = afterDkim.get(selector) ?? null
    if (oldRecord === newRecord) continue
    const kind: DnsDriftKind = oldRecord
      ? newRecord
        ? 'dkim-key-changed'
        : 'dkim-key-removed'
      : 'dkim-key-added'
    pushDrift(
      events,
      {
        kind,
        title:
          kind === 'dkim-key-added'
            ? 'Neuer DKIM-Key'
            : kind === 'dkim-key-removed'
              ? 'DKIM-Key entfernt'
              : 'DKIM-Key geändert',
        detail: `Selector: ${selector}`,
        before: oldRecord,
        after: newRecord,
        selector
      },
      checkedAt
    )
  }

  const beforeBimi = before.bimi ? lines(sortedStrings(before.bimi.records)) : null
  const afterBimi = after.bimi ? lines(sortedStrings(after.bimi.records)) : null
  if (beforeBimi !== afterBimi) {
    pushDrift(
      events,
      {
        kind: 'bimi-changed',
        title: 'BIMI geändert',
        detail: 'Der BIMI-TXT-Record hat sich seit dem letzten Check verändert.',
        before: beforeBimi,
        after: afterBimi
      },
      checkedAt
    )
  }

  return events
}

function detectTransportDrifts(
  before: TransportSecurityResult,
  after: TransportSecurityResult
): PendingDrift[] {
  const events: PendingDrift[] = []
  const checkedAt = after.checkedAt
  const beforeTlsRpt = lines(sortedStrings(before.tlsrpt.records))
  const afterTlsRpt = lines(sortedStrings(after.tlsrpt.records))
  if (beforeTlsRpt !== afterTlsRpt) {
    pushDrift(
      events,
      {
        kind: 'tls-rpt-changed',
        title: 'TLS-RPT geändert',
        detail: 'Der TLS-RPT-TXT-Record hat sich seit dem letzten Check verändert.',
        before: beforeTlsRpt,
        after: afterTlsRpt
      },
      checkedAt
    )
  }

  const beforeMta = stableJson(canonicalHistoryResult('transport', before))
  const afterMta = stableJson(canonicalHistoryResult('transport', after))
  const beforePolicy = stableJson({
    records: sortedStrings(before.mtaSts.records),
    policy: before.mtaSts.policy
  })
  const afterPolicy = stableJson({
    records: sortedStrings(after.mtaSts.records),
    policy: after.mtaSts.policy
  })
  if (beforeMta !== afterMta && beforePolicy !== afterPolicy) {
    pushDrift(
      events,
      {
        kind: 'mta-sts-policy-changed',
        title: 'MTA-STS Policy geändert',
        detail: 'MTA-STS-TXT-Record oder Policy-Datei haben sich verändert.',
        before: beforePolicy,
        after: afterPolicy
      },
      checkedAt
    )
  }
  return events
}

function parseHistoryResult(json: string): HistoryResult | null {
  try {
    return JSON.parse(json) as HistoryResult
  } catch {
    return null
  }
}

function detectDrifts(
  kind: DnsHistorySnapshotKind,
  before: HistoryResult | null,
  after: HistoryResult
): PendingDrift[] {
  if (!before) return []
  if (kind === 'transport') {
    return detectTransportDrifts(
      before as TransportSecurityResult,
      after as TransportSecurityResult
    )
  }
  return detectDnsDrifts(before as DnsCheckResult, after as DnsCheckResult)
}

function recordHistorySnapshot(
  kind: DnsHistorySnapshotKind,
  result: HistoryResult
): DnsDriftEvent[] {
  const database = openDb()
  const domain = domainKey(result.domain)
  const checkedAt = result.checkedAt || new Date().toISOString()
  const resultJson = JSON.stringify(result)
  const fingerprint = snapshotFingerprint(kind, result)
  const previous = database
    .prepare(
      `SELECT result_json, fingerprint
       FROM dns_history_snapshots
       WHERE domain = ? AND kind = ?
       ORDER BY checked_at DESC, id DESC
       LIMIT 1`
    )
    .get(domain, kind) as { result_json: string; fingerprint: string } | undefined
  const previousResult = previous ? parseHistoryResult(previous.result_json) : null
  const pending =
    previous?.fingerprint === fingerprint ? [] : detectDrifts(kind, previousResult, result)
  const events: DnsDriftEvent[] = []

  withTransaction(database, () => {
    const inserted = database
      .prepare(
        `INSERT INTO dns_history_snapshots(domain, kind, checked_at, fingerprint, result_json)
         VALUES (?, ?, ?, ?, ?)`
      )
      .run(domain, kind, checkedAt, fingerprint, resultJson) as { lastInsertRowid: number | bigint }
    const snapshotId = Number(inserted.lastInsertRowid)
    const stmt = database.prepare(
      `INSERT INTO dns_drift_events(
         domain, snapshot_id, kind, checked_at, title, detail, before_value, after_value, selector
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    for (const event of pending) {
      const insertedEvent = stmt.run(
        domain,
        snapshotId,
        event.kind,
        event.checkedAt,
        event.title,
        event.detail,
        event.before,
        event.after,
        event.selector ?? null
      ) as { lastInsertRowid: number | bigint }
      events.push({ ...event, id: Number(insertedEvent.lastInsertRowid), domain })
    }
  })

  return events
}

export function recordDnsHistory(result: DnsCheckResult): DnsDriftEvent[] {
  return recordHistorySnapshot('dns', result)
}

export function recordTransportHistory(result: TransportSecurityResult): DnsDriftEvent[] {
  return recordHistorySnapshot('transport', result)
}

function rowToDrift(row: {
  id: number
  domain: string
  kind: string
  checked_at: string
  title: string
  detail: string
  before_value: string | null
  after_value: string | null
  selector: string | null
}): DnsDriftEvent {
  return {
    id: row.id,
    domain: row.domain,
    kind: row.kind as DnsDriftKind,
    checkedAt: row.checked_at,
    title: row.title,
    detail: row.detail,
    before: row.before_value,
    after: row.after_value,
    ...(row.selector ? { selector: row.selector } : {})
  }
}

function historySnapshotFromRow(row: {
  id: number
  domain: string
  kind: string
  checked_at: string
  result_json: string
}): DnsHistorySnapshot | null {
  const kind = row.kind === 'transport' ? 'transport' : row.kind === 'dns' ? 'dns' : null
  if (!kind) return null
  const parsed = parseHistoryResult(row.result_json)
  if (!parsed) return null
  return {
    id: row.id,
    domain: row.domain,
    kind,
    checkedAt: row.checked_at,
    dns: kind === 'dns' ? (parsed as DnsCheckResult) : null,
    transport: kind === 'transport' ? (parsed as TransportSecurityResult) : null
  }
}

function reportCorrelationForDrifts(
  database: DatabaseSync,
  domain: string,
  drifts: DnsDriftEvent[]
): DnsReportCorrelation[] {
  const reports = database
    .prepare(
      `SELECT report_id, date_begin, date_end, total, failing
       FROM reports
       WHERE domain = ? AND total > 0
       ORDER BY date_end ASC`
    )
    .all(domain) as Array<{
    report_id: string
    date_begin: string
    date_end: string
    total: number
    failing: number
  }>
  if (reports.length < 2) return []

  const out: DnsReportCorrelation[] = []
  for (const drift of drifts) {
    const driftTime = new Date(drift.checkedAt).getTime()
    if (!Number.isFinite(driftTime)) continue
    const before = reports
      .filter((report) => new Date(report.date_end).getTime() <= driftTime)
      .at(-1)
    const after = reports.find((report) => new Date(report.date_end).getTime() > driftTime)
    if (!before || !after) continue
    const beforeRate = (before.failing / before.total) * 100
    const afterRate = (after.failing / after.total) * 100
    const delta = afterRate - beforeRate
    if (delta <= 0) continue
    out.push({
      driftId: drift.id,
      domain,
      driftAt: drift.checkedAt,
      beforeReportId: before.report_id,
      afterReportId: after.report_id,
      beforeWindowEnd: before.date_end,
      afterWindowBegin: after.date_begin,
      beforeFailRate: Math.round(beforeRate * 10) / 10,
      afterFailRate: Math.round(afterRate * 10) / 10,
      deltaPercentagePoints: Math.round(delta * 10) / 10,
      hoursAfter:
        Math.round(((new Date(after.date_end).getTime() - driftTime) / 3_600_000) * 10) / 10
    })
  }
  return out
}

export function getDnsHistory(domainRaw: string): DnsHistoryResult {
  const database = openDb()
  const domain = domainKey(domainRaw)
  const snapshots = (
    database
      .prepare(
        `SELECT id, domain, kind, checked_at, result_json
         FROM dns_history_snapshots
         WHERE domain = ?
         ORDER BY checked_at DESC, id DESC
         LIMIT 200`
      )
      .all(domain) as Array<{
      id: number
      domain: string
      kind: string
      checked_at: string
      result_json: string
    }>
  )
    .map(historySnapshotFromRow)
    .filter((item): item is DnsHistorySnapshot => Boolean(item))
  const drifts = (
    database
      .prepare(
        `SELECT id, domain, kind, checked_at, title, detail, before_value, after_value, selector
         FROM dns_drift_events
         WHERE domain = ?
         ORDER BY checked_at DESC, id DESC
         LIMIT 200`
      )
      .all(domain) as Array<{
      id: number
      domain: string
      kind: string
      checked_at: string
      title: string
      detail: string
      before_value: string | null
      after_value: string | null
      selector: string | null
    }>
  ).map(rowToDrift)
  return {
    domain,
    snapshots,
    drifts,
    correlations: reportCorrelationForDrifts(database, domain, drifts)
  }
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
