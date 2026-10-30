import { createHash } from 'crypto'
import type { DatabaseSync } from 'node:sqlite'
import type {
  DnsCheckResult,
  DnsDriftEvent,
  DnsDriftKind,
  DnsHistoryResult,
  DnsHistorySnapshot,
  DnsHistorySnapshotKind,
  DnsReportCorrelation,
  DomainDkimSelector,
  TransportSecurityResult
} from '../shared/types'

const DNS_HEALTH_TTL_MS = 6 * 60 * 60 * 1000

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

export function recordHistorySnapshotInDb(
  database: DatabaseSync,
  kind: DnsHistorySnapshotKind,
  result: HistoryResult
): DnsDriftEvent[] {
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

export function getCachedReportDomainsInDb(database: DatabaseSync): string[] {
  const rows = database
    .prepare('SELECT DISTINCT domain FROM reports ORDER BY domain')
    .all() as Array<{ domain: string }>
  return [...new Set(rows.map(({ domain }) => domainKey(domain)).filter(Boolean))].sort()
}

export function getLatestDnsHistoryCheckAtInDb(
  database: DatabaseSync,
  domainRaw: string,
  kind: DnsHistorySnapshotKind
): string | null {
  const domain = domainKey(domainRaw)
  const row = database
    .prepare(
      `SELECT checked_at FROM dns_history_snapshots
       WHERE domain = ? AND kind = ?
       ORDER BY checked_at DESC, id DESC LIMIT 1`
    )
    .get(domain, kind) as { checked_at: string } | undefined
  return row?.checked_at ?? null
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
    const after = reports
      .filter((report) => new Date(report.date_begin).getTime() >= driftTime)
      .at(-1)
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

export function getDnsHistoryInDb(database: DatabaseSync, domainRaw: string): DnsHistoryResult {
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

export function getDnsHealthCacheInDb(
  database: DatabaseSync,
  domain: string
): DnsCheckResult | null {
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

export function upsertDnsHealthCacheInDb(
  database: DatabaseSync,
  domain: string,
  result: DnsCheckResult,
  ttlMs = DNS_HEALTH_TTL_MS
): void {
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

export function getDomainDkimSelectorsInDb(
  database: DatabaseSync,
  domain: string
): DomainDkimSelector[] {
  const rows = database
    .prepare(
      `SELECT selector, enabled FROM domain_dkim_selectors
       WHERE domain = ? ORDER BY selector`
    )
    .all(domain.trim().toLowerCase()) as Array<{ selector: string; enabled: number }>
  return rows.map(({ selector, enabled }) => ({ selector, enabled: enabled === 1 }))
}

export function addDiscoveredDomainDkimSelectorsInDb(
  database: DatabaseSync,
  domain: string,
  selectors: string[]
): void {
  const statement = database.prepare(
    `INSERT INTO domain_dkim_selectors(domain, selector, enabled)
     VALUES (?, ?, 1) ON CONFLICT(domain, selector) DO NOTHING`
  )
  const normalizedDomain = domain.trim().toLowerCase()
  for (const selector of selectors) {
    statement.run(normalizedDomain, selector)
  }
}

export function saveDomainDkimSelectorsInDb(
  database: DatabaseSync,
  domain: string,
  selectors: DomainDkimSelector[]
): void {
  const normalizedDomain = domain.trim().toLowerCase()
  database.exec('BEGIN')
  try {
    database.prepare('DELETE FROM domain_dkim_selectors WHERE domain = ?').run(normalizedDomain)
    const insert = database.prepare(
      `INSERT INTO domain_dkim_selectors(domain, selector, enabled) VALUES (?, ?, ?)`
    )
    for (const { selector, enabled } of selectors) {
      insert.run(normalizedDomain, selector, enabled ? 1 : 0)
    }
    database.exec('COMMIT')
  } catch (error) {
    database.exec('ROLLBACK')
    throw error
  }
}
