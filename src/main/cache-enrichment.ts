import { randomUUID } from 'crypto'
import type { DatabaseSync } from 'node:sqlite'
import { matchSendingService } from '../shared/sending-services'
import type { IpInfo, SenderKind, SendingService, SendingServiceInput } from '../shared/types'

export const IP_ENRICHMENT_TTL_MS = 7 * 24 * 60 * 60 * 1000

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

export function rowToSendingService(row: {
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

export function listSendingServicesInDb(database: DatabaseSync): SendingService[] {
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

export type HistoricalSendingSource = {
  account_key: string
  source_ip: string
  domain: string | null
  provider: string | null
  asn: number | null
}

export function historicalSourcesForService(
  database: DatabaseSync,
  service: SendingService
): HistoricalSendingSource[] {
  const candidates = database
    .prepare(
      `SELECT DISTINCT
         rr.account_key,
         rr.source_ip,
         COALESCE(NULLIF(rr.header_from, ''), r.domain) AS domain,
         ie.provider,
         ie.asn
       FROM report_records rr
       JOIN reports r
         ON r.account_key = rr.account_key AND r.report_id = rr.report_id
       LEFT JOIN ip_enrichment ie ON ie.ip = rr.source_ip`
    )
    .all() as HistoricalSendingSource[]
  return candidates.filter((candidate) =>
    matchSendingService([service], {
      provider: candidate.provider,
      domain: candidate.domain,
      ip: candidate.source_ip,
      asn: candidate.asn
    })
  )
}

export function reopenHistoricalSources(
  database: DatabaseSync,
  candidates: readonly HistoricalSendingSource[]
): void {
  const insertPending = database.prepare(
    `INSERT INTO pending_source_ips(account_key, source_ip, discovered_at) VALUES (?, ?, ?)
     ON CONFLICT(account_key, source_ip) DO NOTHING`
  )
  const discoveredAt = new Date().toISOString()
  for (const candidate of candidates) {
    insertPending.run(candidate.account_key, candidate.source_ip, discoveredAt)
  }
}

export function upsertSendingServiceInDb(
  database: DatabaseSync,
  input: SendingServiceInput
): SendingService {
  const now = new Date().toISOString()
  const id = input.id && input.id.trim() ? input.id : randomUUID()
  const existingRow = database
    .prepare(
      `SELECT id, provider, domain, cidr, asn, status, note, team, created_at, updated_at
       FROM sending_services WHERE id = ?`
    )
    .get(id) as
    | {
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
      }
    | undefined
  const existing = existingRow ? rowToSendingService(existingRow) : null
  const createdAt = existing?.createdAt ?? now
  const updated: SendingService = {
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
  const reopen =
    existing?.status === 'known'
      ? historicalSourcesForService(database, existing).filter(
          (candidate) =>
            updated.status !== 'known' ||
            !matchSendingService([updated], {
              provider: candidate.provider,
              domain: candidate.domain,
              ip: candidate.source_ip,
              asn: candidate.asn
            })
        )
      : []
  withTransaction(database, () => {
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
    reopenHistoricalSources(database, reopen)
  })
  return updated
}

export function deleteSendingServiceInDb(database: DatabaseSync, id: string): number {
  const row = database
    .prepare(
      `SELECT id, provider, domain, cidr, asn, status, note, team, created_at, updated_at
       FROM sending_services WHERE id = ?`
    )
    .get(id) as
    | {
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
      }
    | undefined
  if (!row) return 0

  const service = rowToSendingService(row)
  const reopened = service.status === 'known' ? historicalSourcesForService(database, service) : []
  withTransaction(database, () => {
    database.prepare('DELETE FROM sending_services WHERE id = ?').run(id)
    reopenHistoricalSources(database, reopened)
  })
  return reopened.length
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

export function getIpEnrichmentInDb(database: DatabaseSync, ips: string[]): Map<string, IpInfo> {
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

export function upsertIpEnrichmentInDb(
  database: DatabaseSync,
  infos: IpInfo[],
  ttlMs = IP_ENRICHMENT_TTL_MS
): void {
  if (infos.length === 0) return
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
