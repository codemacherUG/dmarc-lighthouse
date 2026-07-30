import { app } from 'electron'
import { createHash } from 'crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs'
import { join } from 'path'
import type { ReportRow } from '../shared/types'

export interface CacheMeta {
  accountKey: string
  lastUid: number
  lastFetchAt: string | null
  lastFailingTotal: number
  knownSourceIps: string[]
}

interface CacheFile {
  version: 1
  accountKey: string
  lastUid: number
  lastFetchAt: string | null
  lastFailingTotal: number
  knownSourceIps?: string[]
  reports: ReportRow[]
}

function cacheDir(): string {
  const dir = join(app.getPath('userData'), 'cache')
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
  return dir
}

function cachePath(accountKey: string): string {
  return join(cacheDir(), `${accountKey}.json`)
}

export function accountKeyFor(user: string, host: string, mailbox: string): string {
  const raw = `${user.trim().toLowerCase()}@${host.trim().toLowerCase()}/${mailbox.trim()}`
  return createHash('sha256').update(raw).digest('hex').slice(0, 24)
}

function emptyCache(accountKey: string): CacheFile {
  return {
    version: 1,
    accountKey,
    lastUid: 0,
    lastFetchAt: null,
    lastFailingTotal: 0,
    reports: []
  }
}

function readCacheFile(accountKey: string): CacheFile {
  const path = cachePath(accountKey)
  if (!existsSync(path)) return emptyCache(accountKey)
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as CacheFile
    if (parsed.version !== 1 || !Array.isArray(parsed.reports)) {
      return emptyCache(accountKey)
    }
    return {
      ...emptyCache(accountKey),
      ...parsed,
      accountKey,
      reports: (parsed.reports ?? []).map((r) => ({
        ...r,
        records: (r.records ?? []).map((rec) => ({
          ...rec,
          reasons: rec.reasons ?? [],
          dkimSelectors: rec.dkimSelectors ?? []
        }))
      }))
    }
  } catch {
    return emptyCache(accountKey)
  }
}

function writeCacheFile(cache: CacheFile): void {
  writeFileSync(cachePath(cache.accountKey), JSON.stringify(cache), 'utf8')
}

export function loadCachedReports(accountKey: string): {
  reports: ReportRow[]
  meta: CacheMeta
} {
  const cache = readCacheFile(accountKey)
  return {
    reports: cache.reports,
    meta: {
      accountKey: cache.accountKey,
      lastUid: cache.lastUid,
      lastFetchAt: cache.lastFetchAt,
      lastFailingTotal: cache.lastFailingTotal,
      knownSourceIps: cache.knownSourceIps ?? []
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

export function saveCache(input: {
  accountKey: string
  reports: ReportRow[]
  lastUid: number
  lastFailingTotal: number
  knownSourceIps: string[]
}): CacheMeta {
  const cache: CacheFile = {
    version: 1,
    accountKey: input.accountKey,
    lastUid: input.lastUid,
    lastFetchAt: new Date().toISOString(),
    lastFailingTotal: input.lastFailingTotal,
    knownSourceIps: input.knownSourceIps,
    reports: input.reports
  }
  writeCacheFile(cache)
  return {
    accountKey: cache.accountKey,
    lastUid: cache.lastUid,
    lastFetchAt: cache.lastFetchAt,
    lastFailingTotal: cache.lastFailingTotal,
    knownSourceIps: cache.knownSourceIps ?? []
  }
}

export function clearCache(accountKey: string): void {
  writeCacheFile(emptyCache(accountKey))
}
