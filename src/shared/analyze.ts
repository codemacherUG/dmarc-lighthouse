import type {
  AlignmentBreakdown,
  AnalyzeResult,
  DashboardData,
  DashboardFilter,
  DateRangePreset,
  DispositionFilter,
  DnsCheckResult,
  DomainHealth,
  DomainHealthStatus,
  DomainStats,
  FailCategory,
  FailCategoryCounts,
  ForensicReportRow,
  IpInfo,
  NamedBucket,
  ProblemSourceRow,
  ReportRow,
  SerializedRecord,
  VolumePoint
} from './types'
import { isRelaxedAligned } from './domain'
import {
  isLikelyMailboxIp,
  type MailboxNoiseProvider
} from './mailbox-ip'
import { matchesScannerNoise, type ScannerNoiseMatcher } from './scanner-noise'
import { emptyAnalyzeResult, emptyDashboard } from './types'

type MailboxIpInfo = Pick<IpInfo, 'cloudProvider' | 'provider' | 'asn' | 'asOrg' | 'senderKind'>

/** True when enrichment labels the IP as Google (cloud, PTR, or ASN). */
export function isGoogleIpInfo(
  info: Pick<IpInfo, 'cloudProvider' | 'provider' | 'asn' | 'asOrg'> | null | undefined
): boolean {
  if (!info) return false
  if (info.cloudProvider === 'Google' || info.provider === 'Google') return true
  if (info.asn === 15169) return true
  if (info.asOrg && /\bgoogle\b/i.test(info.asOrg)) return true
  return false
}

/** Which mailbox-noise family enrichment assigned, if any. */
export function mailboxNoiseProviderFromInfo(
  info: MailboxIpInfo | null | undefined
): MailboxNoiseProvider | null {
  if (!info) return null
  if (isGoogleIpInfo(info)) return 'google'
  const provider = (info.provider ?? '').toLowerCase()
  if (/\b(microsoft 365|outlook|hotmail)\b/.test(provider)) return 'microsoft'
  if (/\b(yahoo|aol)\b/.test(provider)) return 'yahoo'
  if (/\bicloud\b/.test(provider)) return 'apple'
  if (
    info.asn === 10310 ||
    info.asn === 26101 ||
    info.asn === 14778 ||
    info.asn === 1668
  ) {
    return 'yahoo'
  }
  if (info.asn === 714) return 'apple'
  if (info.asOrg && /\b(yahoo|aol|oath|verizon media)\b/i.test(info.asOrg)) return 'yahoo'
  if (info.asOrg && /\b(apple|icloud)\b/i.test(info.asOrg)) return 'apple'
  if (info.asOrg && /\b(hotmail|outlook)\b/i.test(info.asOrg)) return 'microsoft'
  if (info.senderKind === 'mailbox') return 'other'
  return null
}

/** True when enrichment labels the IP as an enabled mailbox provider. */
export function isMailboxIpInfo(
  info: MailboxIpInfo | null | undefined,
  enabled?: ReadonlySet<MailboxNoiseProvider>
): boolean {
  const family = mailboxNoiseProviderFromInfo(info)
  if (!family) return false
  return !enabled || enabled.has(family)
}

/** Auth pattern of mailbox forwarding / report-echo noise (IP not checked). */
export function isMailboxNoiseAuthPattern(rec: SerializedRecord): boolean {
  if (!rec.passesDmarc) return false
  const spf = (rec.spfResult ?? '').toLowerCase()
  const dkim = (rec.dkimResult ?? '').toLowerCase()
  return spf === 'fail' && dkim === 'pass'
}

/**
 * Recipient-scanner re-injection: the hop after inline scanning.
 * Unlike mailbox forwarding, DKIM usually does not survive, so DMARC fails too.
 * Reject/quarantine stays visible — that is enforcement, not scanner echo.
 */
export function isScannerNoiseAuthPattern(rec: SerializedRecord): boolean {
  if (rec.passesDmarc) return false
  const disp = (rec.disposition ?? 'none').toLowerCase()
  if (disp === 'reject' || disp === 'quarantine') return false
  return (rec.spfResult ?? '').toLowerCase() === 'fail'
}

/** True when the IP is listed or its PTR matches the configured scanner-noise hosts. */
export function isScannerNoiseIpInfo(
  info: (Pick<IpInfo, 'ptr'> & Partial<Pick<IpInfo, 'ip'>>) | null | undefined,
  matchers: readonly ScannerNoiseMatcher[]
): boolean {
  if (!info || matchers.length === 0) return false
  return matchesScannerNoise(info.ip, info.ptr, matchers)
}

/**
 * Mailbox-provider hop / report-echo noise: SPF fails on a Gmail/Outlook/Yahoo/iCloud IP,
 * DKIM holds, DMARC passes. Also recipient-scanner re-injection (SPF fail, usually
 * DKIM fail too) once enrichment has named the IP. Uses well-known mailbox prefixes
 * when enrichment is missing.
 */
export function isMailboxNoiseRecord(
  rec: SerializedRecord,
  mailboxIps?: ReadonlySet<string>,
  scannerNoiseIps?: ReadonlySet<string>,
  mailboxProviders?: ReadonlySet<MailboxNoiseProvider>
): boolean {
  if (isMailboxNoiseAuthPattern(rec)) {
    if (mailboxIps?.has(rec.sourceIp) || isLikelyMailboxIp(rec.sourceIp, mailboxProviders)) {
      return true
    }
  }
  if (isScannerNoiseAuthPattern(rec) && scannerNoiseIps?.has(rec.sourceIp)) return true
  return false
}

function dayKey(iso: string): string {
  if (!iso) return 'unbekannt'
  return iso.slice(0, 10)
}

function alignmentBucket(value: string | null | undefined): keyof AlignmentBreakdown {
  if (value === 'pass') return 'pass'
  if (value === 'fail') return 'fail'
  return 'other'
}

function bumpNamed(
  map: Map<string, { count: number; passing: number; failing: number; delivered: number }>,
  name: string,
  count: number,
  passes: boolean,
  delivered: boolean
): void {
  const key = name || '(unbekannt)'
  const cur = map.get(key) ?? { count: 0, passing: 0, failing: 0, delivered: 0 }
  cur.count += count
  if (passes) cur.passing += count
  else cur.failing += count
  if (delivered) cur.delivered += count
  map.set(key, cur)
}

function toNamedBuckets(
  map: Map<string, { count: number; passing: number; failing: number; delivered: number }>,
  limit = 25
): NamedBucket[] {
  return [...map.entries()]
    .map(([name, v]) => ({
      name,
      count: v.count,
      passing: v.passing,
      failing: v.failing,
      delivered: v.delivered,
      passRate: v.count ? Math.round((v.passing / v.count) * 1000) / 10 : 0
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit)
}

/** Receiver overrides that mark a failure as forwarding rather than abuse. */
const FORWARDING_REASONS = new Set([
  'forwarded',
  'mailing_list',
  'trusted_forwarder',
  'local_policy'
])

/**
 * Why a delivered message failed DMARC. `dkimResult` / `spfResult` are the
 * *aligned* results from policy_evaluated, so a failing record failed both;
 * the auth-result domains tell us which of these four situations it is.
 */
export function categorizeFailure(rec: SerializedRecord, policyDomain?: string): FailCategory {
  for (const reason of rec.reasons ?? []) {
    if (FORWARDING_REASONS.has((reason.type ?? '').toLowerCase())) return 'forwarder'
  }

  const from = rec.headerFrom || policyDomain || null
  const dkimDomain = rec.dkimDomain?.trim() || null
  const spfDomain = rec.spfDomain?.trim() || null

  if (!dkimDomain && !spfDomain) return 'unauthenticated'

  const dkimForeign = Boolean(dkimDomain) && !isRelaxedAligned(dkimDomain, from)
  const spfForeign = Boolean(spfDomain) && !isRelaxedAligned(spfDomain, from)
  // Signed or sent under someone else's domain: an ESP without alignment setup.
  if ((dkimDomain ? dkimForeign : true) && (spfDomain ? spfForeign : true)) return 'thirdParty'

  // Own domain authenticated but alignment/verification still failed.
  return 'broken'
}

function topCategory(counts: FailCategoryCounts): FailCategory | null {
  let best: FailCategory | null = null
  let bestCount = 0
  for (const [category, count] of Object.entries(counts) as Array<[FailCategory, number]>) {
    if (count > bestCount) {
      bestCount = count
      best = category
    }
  }
  return best
}

function addCategoryCounts(
  target: FailCategoryCounts,
  source: FailCategoryCounts
): FailCategoryCounts {
  for (const [category, count] of Object.entries(source) as Array<[FailCategory, number]>) {
    target[category] = (target[category] ?? 0) + count
  }
  return target
}

/**
 * IPs with unhealthy DMARC outcomes for rollout review
 * (delivered auth-fails; reject/quarantine / local_policy excluded).
 */
export function buildProblemSources(reports: ReportRow[], limit = 200): ProblemSourceRow[] {
  type Acc = {
    count: number
    spfFail: number
    dkimFail: number
    fromCounts: Map<string, number>
    categories: FailCategoryCounts
  }
  const map = new Map<string, Acc>()

  for (const report of reports) {
    for (const rec of report.records) {
      if (isHealthyDmarcOutcome(rec)) continue
      const ip = (rec.sourceIp || '').trim() || '(unbekannt)'
      const n = rec.count || 0
      const cur = map.get(ip) ?? {
        count: 0,
        spfFail: 0,
        dkimFail: 0,
        fromCounts: new Map(),
        categories: {} as FailCategoryCounts
      }
      cur.count += n
      if ((rec.spfResult ?? '').toLowerCase() !== 'pass') cur.spfFail += n
      if ((rec.dkimResult ?? '').toLowerCase() !== 'pass') cur.dkimFail += n
      const from = (rec.headerFrom || '').trim() || '(unbekannt)'
      cur.fromCounts.set(from, (cur.fromCounts.get(from) ?? 0) + n)
      const category = categorizeFailure(rec, report.domain)
      cur.categories[category] = (cur.categories[category] ?? 0) + n
      map.set(ip, cur)
    }
  }

  return [...map.entries()]
    .map(([sourceIp, v]) => {
      let headerFrom: string | null = null
      let best = 0
      for (const [from, c] of v.fromCounts) {
        if (c > best) {
          best = c
          headerFrom = from
        }
      }
      return {
        sourceIp,
        count: v.count,
        spfFail: v.spfFail,
        dkimFail: v.dkimFail,
        headerFrom,
        categories: v.categories,
        category: topCategory(v.categories)
      }
    })
    .sort((a, b) => b.count - a.count)
    .slice(0, limit)
}

export type ProblemSourceIpInfo = Pick<IpInfo, 'asn' | 'provider' | 'cloudProvider'>

function problemSourceNetworkKey(info: ProblemSourceIpInfo | null | undefined): string | null {
  if (info?.asn != null) return `as:${info.asn}`
  const cloud = info?.cloudProvider?.trim()
  if (cloud) return `cloud:${cloud.toLowerCase()}`
  const provider = info?.provider?.trim()
  if (provider) return `prov:${provider.toLowerCase()}`
  return null
}

/**
 * Collapse problem IPs that share a network (ASN / cloud / provider) and the same From.
 * Unenriched IPs stay separate so the table can regroup after lookup.
 */
export function groupProblemSources(
  rows: ProblemSourceRow[],
  infoFor: (ip: string) => ProblemSourceIpInfo | null | undefined
): ProblemSourceRow[] {
  type Acc = {
    sourceIp: string
    count: number
    spfFail: number
    dkimFail: number
    headerFrom: string | null
    ips: string[]
    topCount: number
    categories: FailCategoryCounts
  }
  const map = new Map<string, Acc>()
  for (const row of rows) {
    const net = problemSourceNetworkKey(infoFor(row.sourceIp))
    const key = `${net ?? `ip:${row.sourceIp}`}|${row.headerFrom ?? ''}`
    const cur = map.get(key)
    if (!cur) {
      map.set(key, {
        sourceIp: row.sourceIp,
        count: row.count,
        spfFail: row.spfFail,
        dkimFail: row.dkimFail,
        headerFrom: row.headerFrom,
        ips: [row.sourceIp],
        topCount: row.count,
        categories: addCategoryCounts({}, row.categories ?? {})
      })
      continue
    }
    cur.count += row.count
    cur.spfFail += row.spfFail
    cur.dkimFail += row.dkimFail
    cur.ips.push(row.sourceIp)
    addCategoryCounts(cur.categories, row.categories ?? {})
    if (row.count > cur.topCount) {
      cur.sourceIp = row.sourceIp
      cur.topCount = row.count
    }
  }
  return [...map.values()]
    .map((v) => {
      const extraIps = v.ips.filter((ip) => ip !== v.sourceIp)
      return {
        sourceIp: v.sourceIp,
        count: v.count,
        spfFail: v.spfFail,
        dkimFail: v.dkimFail,
        headerFrom: v.headerFrom,
        categories: v.categories,
        category: topCategory(v.categories),
        ...(extraIps.length ? { extraIps } : {})
      }
    })
    .sort((a, b) => b.count - a.count)
}

/** Parse a single IP or a comma-separated group used as drill-down filter. */
export function parseSourceIpFilter(sourceIp: string | undefined): string[] | null {
  if (!sourceIp?.trim()) return null
  const ips = sourceIp
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
  return ips.length ? ips : null
}

export function normalizeDispositionFilter(value: unknown): DispositionFilter {
  return value === 'reject' || value === 'not-reject' ? value : 'all'
}

/** True when the applied disposition (or forensic Delivery-Result) is reject. */
export function isRejectDisposition(value: string | null | undefined): boolean {
  const v = (value ?? '').trim().toLowerCase()
  return v === 'reject' || v === 'rejected'
}

export function matchesDispositionFilter(
  value: string | null | undefined,
  filter: DispositionFilter | undefined
): boolean {
  const mode = normalizeDispositionFilter(filter)
  if (mode === 'all') return true
  const rejected = isRejectDisposition(value)
  return mode === 'reject' ? rejected : !rejected
}

export function recordMatchesSourceIp(recIp: string, filter: string | undefined): boolean {
  const ips = parseSourceIpFilter(filter)
  if (!ips) return true
  if (ips.length === 1) return recIp === ips[0]
  return ips.includes(recIp)
}

export function buildDashboard(reports: ReportRow[]): DashboardData {
  if (reports.length === 0) return emptyDashboard()

  const dmarc: AlignmentBreakdown = { pass: 0, fail: 0, other: 0 }
  const spf: AlignmentBreakdown = { pass: 0, fail: 0, other: 0 }
  const dkim: AlignmentBreakdown = { pass: 0, fail: 0, other: 0 }
  const dispositionMap = new Map<string, { count: number; passing: number; failing: number; delivered: number }>()
  const byOrg = new Map<string, { count: number; passing: number; failing: number; delivered: number }>()
  const bySourceIp = new Map<string, { count: number; passing: number; failing: number; delivered: number }>()
  const byHeaderFrom = new Map<string, { count: number; passing: number; failing: number; delivered: number }>()
  const volumeMap = new Map<string, VolumePoint>()

  for (const report of reports) {
    const day = dayKey(report.dateEnd || report.dateBegin)
    const vol = volumeMap.get(day) ?? {
      date: day,
      total: 0,
      passing: 0,
      failing: 0,
      passRate: 0
    }
    vol.total += report.total
    vol.passing += report.passing
    vol.failing += report.failing
    vol.passRate = vol.total ? Math.round((vol.passing / vol.total) * 1000) / 10 : 0
    volumeMap.set(day, vol)

    for (const rec of report.records) {
      const n = rec.count || 0
      dmarc[rec.passesDmarc ? 'pass' : 'fail'] += n
      spf[alignmentBucket(rec.spfResult)] += n
      dkim[alignmentBucket(rec.dkimResult)] += n
      const delivered = (rec.disposition ?? 'none') === 'none'
      bumpNamed(dispositionMap, rec.disposition ?? 'none', n, rec.passesDmarc, delivered)
      bumpNamed(byOrg, report.orgName, n, rec.passesDmarc, delivered)
      bumpNamed(bySourceIp, rec.sourceIp, n, rec.passesDmarc, delivered)
      bumpNamed(byHeaderFrom, rec.headerFrom ?? '(unbekannt)', n, rec.passesDmarc, delivered)
    }
  }

  return {
    dmarc,
    spf,
    dkim,
    dispositions: toNamedBuckets(dispositionMap, 10),
    byOrg: toNamedBuckets(byOrg, 25),
    bySourceIp: toNamedBuckets(bySourceIp, 40),
    byHeaderFrom: toNamedBuckets(byHeaderFrom, 25),
    volumeByDay: [...volumeMap.values()].sort((a, b) => a.date.localeCompare(b.date)),
    problemSources: buildProblemSources(reports, 40)
  }
}

export function analyzeFromReports(
  reports: ReportRow[],
  extras?: {
    skipped?: number
    errors?: string[]
    fromCache?: boolean
    newReports?: number
    newForensicReports?: number
    forensicReports?: ForensicReportRow[]
  }
): AnalyzeResult {
  const forensicReports = extras?.forensicReports ?? []
  if (reports.length === 0) {
    return {
      ...emptyAnalyzeResult(),
      forensicReports,
      skipped: extras?.skipped ?? 0,
      errors: extras?.errors ?? [],
      fromCache: extras?.fromCache,
      newReports: extras?.newReports ?? 0,
      newForensicReports: extras?.newForensicReports ?? 0
    }
  }

  let total = 0
  let passing = 0
  let failing = 0
  let dateBegin: string | null = null
  let dateEnd: string | null = null
  const domains = new Set<string>()

  for (const r of reports) {
    total += r.total
    passing += r.passing
    failing += r.failing
    if (r.domain) domains.add(r.domain)
    if (r.dateBegin && (!dateBegin || r.dateBegin < dateBegin)) dateBegin = r.dateBegin
    if (r.dateEnd && (!dateEnd || r.dateEnd > dateEnd)) dateEnd = r.dateEnd
  }

  return {
    aggregate: {
      reportCount: reports.length,
      total,
      passing,
      failing,
      passRate: total ? Math.round((passing / total) * 1000) / 10 : 0,
      dateBegin,
      dateEnd,
      domains: [...domains].sort()
    },
    dashboard: buildDashboard(reports),
    reports,
    forensicReports,
    skipped: extras?.skipped ?? 0,
    errors: extras?.errors ?? [],
    fromCache: extras?.fromCache,
    newReports: extras?.newReports,
    newForensicReports: extras?.newForensicReports
  }
}

function rangeCutoff(range: DateRangePreset): Date | null {
  if (range === 'all' || range === 'custom') return null
  const days = Number(range)
  if (!Number.isFinite(days) || days <= 0) return null
  return daysAgoCutoff(days)
}

/** Midnight-local cutoff for "last N days" windows (dashboard presets & Ampel). */
export function daysAgoCutoff(days: number): Date {
  const d = new Date()
  d.setHours(0, 0, 0, 0)
  d.setDate(d.getDate() - days)
  return d
}

/** Fixed window for Domain-Ampel pass-rate / status (independent of dashboard range). */
export const DOMAIN_HEALTH_WINDOW_DAYS = 14

/** Reports whose window ends within the last `days` days (dateEnd, fallback dateBegin). */
export function filterReportsLastDays(reports: ReportRow[], days: number): ReportRow[] {
  if (days <= 0) return reports
  const cutoffMs = daysAgoCutoff(days).getTime()
  return reports.filter((r) => {
    const end = r.dateEnd || r.dateBegin
    if (!end) return false
    const t = new Date(end).getTime()
    return !Number.isNaN(t) && t >= cutoffMs
  })
}

/** Report slice used for Domain-Ampel volume and pass-rate. */
export function reportsForDomainHealth(reports: ReportRow[]): ReportRow[] {
  return filterReportsLastDays(reports, DOMAIN_HEALTH_WINDOW_DAYS)
}

function inCustomDayRange(
  iso: string | null | undefined,
  from: string | undefined,
  to: string | undefined
): boolean {
  if (!iso) return false
  const day = dayKey(iso)
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) return false
  if (from && day < from) return false
  if (to && day > to) return false
  return true
}

const UNKNOWN = '(unbekannt)'

/** Rebuild a report row after its records were filtered (drill-down). */
function withRecords(report: ReportRow, records: ReportRow['records']): ReportRow {
  let total = 0
  let passing = 0
  for (const rec of records) {
    total += rec.count || 0
    if (rec.passesDmarc) passing += rec.count || 0
  }
  return {
    ...report,
    records,
    total,
    passing,
    failing: total - passing,
    passRate: total ? Math.round((passing / total) * 1000) / 10 : 0
  }
}

export function filterReports(reports: ReportRow[], filter: DashboardFilter): ReportRow[] {
  const cutoff = rangeCutoff(filter.range)
  const customRange = filter.range === 'custom'
  const domain = filter.domain.trim().toLowerCase()
  const org = filter.org?.trim()
  const sourceIp = filter.sourceIp?.trim()
  const headerFrom = filter.headerFrom?.trim()
  const hideMailboxNoise = Boolean(filter.hideMailboxNoise)
  const mailboxIps = filter.mailboxIps
  const scannerNoiseIps = filter.scannerNoiseIps
  const mailboxProviders = filter.mailboxNoiseProviders
  const disposition = normalizeDispositionFilter(filter.disposition)
  const filterDisposition = disposition !== 'all'

  const rows: ReportRow[] = []
  for (const r of reports) {
    if (domain && r.domain.toLowerCase() !== domain) continue
    if (org && (r.orgName || UNKNOWN) !== org) continue

    const end = r.dateEnd || r.dateBegin
    if (customRange && (filter.from || filter.to)) {
      if (!inCustomDayRange(end, filter.from, filter.to)) continue
    } else if (cutoff) {
      if (!end) continue
      const t = new Date(end).getTime()
      if (Number.isNaN(t) || t < cutoff.getTime()) continue
    }

    if (sourceIp || headerFrom || hideMailboxNoise || filterDisposition) {
      const records = r.records.filter((rec) => {
        if (sourceIp && !recordMatchesSourceIp(rec.sourceIp, sourceIp)) return false
        if (headerFrom && (rec.headerFrom ?? UNKNOWN) !== headerFrom) return false
        if (
          hideMailboxNoise &&
          isMailboxNoiseRecord(rec, mailboxIps, scannerNoiseIps, mailboxProviders)
        ) {
          return false
        }
        if (filterDisposition && !matchesDispositionFilter(rec.disposition, disposition)) {
          return false
        }
        return true
      })
      if (records.length === 0) continue
      rows.push(withRecords(r, records))
    } else {
      rows.push(r)
    }
  }
  return rows
}

export function filterForensicReports(
  reports: ForensicReportRow[],
  filter: DashboardFilter
): ForensicReportRow[] {
  const cutoff = rangeCutoff(filter.range)
  const customRange = filter.range === 'custom'
  const domain = filter.domain.trim().toLowerCase()
  const sourceIp = filter.sourceIp?.trim()
  const headerFrom = filter.headerFrom?.trim()
  const disposition = normalizeDispositionFilter(filter.disposition)
  const filterDisposition = disposition !== 'all'

  return reports.filter((r) => {
    if (domain && (r.reportedDomain ?? '').toLowerCase() !== domain) return false
    if (sourceIp && !recordMatchesSourceIp(r.sourceIp ?? '', sourceIp)) return false
    if (headerFrom && (r.headerFrom ?? UNKNOWN) !== headerFrom) return false
    if (filterDisposition && !matchesDispositionFilter(r.deliveryResult, disposition)) return false
    const end = r.arrivalDate
    if (customRange && (filter.from || filter.to)) {
      if (!inCustomDayRange(end, filter.from, filter.to)) return false
    } else if (cutoff) {
      if (!end) return false
      const t = new Date(end).getTime()
      if (Number.isNaN(t) || t < cutoff.getTime()) return false
    }
    return true
  })
}

function dropScannerNoiseProblemSources(
  result: AnalyzeResult,
  scannerNoiseIps: ReadonlySet<string> | undefined
): AnalyzeResult {
  if (!scannerNoiseIps?.size) return result
  const next = result.dashboard.problemSources.filter((row) => !scannerNoiseIps.has(row.sourceIp))
  if (next.length === result.dashboard.problemSources.length) return result
  return {
    ...result,
    dashboard: { ...result.dashboard, problemSources: next }
  }
}

export function applyDashboardFilter(full: AnalyzeResult, filter: DashboardFilter): AnalyzeResult {
  const filtered = filterReports(full.reports, filter)
  const forensicReports = filterForensicReports(full.forensicReports ?? [], filter)
  const mutatesRecords = Boolean(
    filter.sourceIp?.trim() ||
    filter.headerFrom?.trim() ||
    filter.hideMailboxNoise ||
    (filter.disposition && filter.disposition !== 'all')
  )
  if (
    !mutatesRecords &&
    filtered.length === full.reports.length &&
    forensicReports.length === (full.forensicReports?.length ?? 0)
  ) {
    return dropScannerNoiseProblemSources(full, filter.scannerNoiseIps)
  }
  return dropScannerNoiseProblemSources(
    analyzeFromReports(filtered, {
      skipped: full.skipped,
      errors: full.errors,
      fromCache: full.fromCache,
      newReports: full.newReports,
      newForensicReports: full.newForensicReports,
      forensicReports
    }),
    filter.scannerNoiseIps
  )
}

/**
 * Ampel-outcome: not every DMARC auth-fail is a domain problem.
 * - Auth pass → healthy
 * - Auth fail + reject/quarantine → policy doing its job → healthy
 * - Auth fail + local_policy / trusted_forwarder → receiver override (e.g. ARC) → healthy
 * - Auth fail + disposition none (delivered) → unhealthy
 */
export function isHealthyDmarcOutcome(rec: SerializedRecord): boolean {
  if (rec.passesDmarc) return true
  const disp = (rec.disposition ?? 'none').toLowerCase()
  if (disp === 'reject' || disp === 'quarantine') return true
  for (const reason of rec.reasons ?? []) {
    const type = (reason.type ?? '').toLowerCase()
    if (type === 'local_policy' || type === 'trusted_forwarder') return true
  }
  return false
}

/** Aggregate per-domain Ampel stats from records (healthy-outcome rate, not raw DMARC pass rate). */
export function buildDomainStats(reports: ReportRow[]): DomainStats[] {
  const map = new Map<
    string,
    {
      total: number
      passing: number
      failing: number
      selectors: Set<string>
    }
  >()
  for (const r of reports) {
    const domain = (r.domain || '').trim().toLowerCase()
    if (!domain) continue
    const cur = map.get(domain) ?? {
      total: 0,
      passing: 0,
      failing: 0,
      selectors: new Set<string>()
    }
    for (const rec of r.records) {
      for (const sel of rec.dkimSelectors ?? []) {
        if (sel) cur.selectors.add(sel)
      }
      const n = rec.count || 0
      cur.total += n
      if (isHealthyDmarcOutcome(rec)) cur.passing += n
      else cur.failing += n
    }
    map.set(domain, cur)
  }
  return [...map.entries()]
    .map(([domain, v]) => ({
      domain,
      total: v.total,
      passing: v.passing,
      failing: v.failing,
      passRate: v.total ? Math.round((v.passing / v.total) * 1000) / 10 : 100,
      dkimSelectors: [...v.selectors].sort()
    }))
    .sort((a, b) => b.total - a.total)
}

/**
 * Merge Ampel stats (healthy-outcome rate) with a DNS check into status.
 * Rules:
 * - bad: no DMARC, or health rate &lt; 90%, or no SPF
 * - warn: p=none, or health rate 90–98%, or DKIM selectors missing in DNS
 * - ok: quarantine/reject, SPF ok, health rate ≥ 98%
 * - unknown: no DNS result yet
 */
export function mergeDomainHealth(stats: DomainStats, dns: DnsCheckResult | null): DomainHealth {
  if (!dns) {
    return {
      ...stats,
      dmarcPolicy: null,
      spfOk: null,
      dkimOk: null,
      status: 'unknown',
      reasons: ['health.reason.dnsPending']
    }
  }

  const dmarcFound = dns.dmarc.found
  const policy = dns.dmarc.policy?.toLowerCase() ?? null
  const spfOk = dns.spf.found
  const selectors = dns.dkim.selectors
  const dkimOk = selectors.length === 0 ? null : selectors.every((s) => s.found)

  const reasons: string[] = []
  let status: DomainHealthStatus = 'ok'

  if (!dmarcFound) {
    status = 'bad'
    reasons.push('health.reason.noDmarc')
  }
  if (!spfOk) {
    status = 'bad'
    reasons.push('health.reason.noSpf')
  }
  if (stats.total > 0 && stats.passRate < 90) {
    status = 'bad'
    reasons.push('health.reason.lowPassRate')
  }

  if (status !== 'bad') {
    if (policy === 'none') {
      status = 'warn'
      reasons.push('health.reason.policyNone')
    }
    if (stats.total > 0 && stats.passRate < 98) {
      status = 'warn'
      reasons.push('health.reason.passRateWarn')
    }
    if (dkimOk === false) {
      status = 'warn'
      reasons.push('health.reason.dkimMissing')
    }
  }

  if (status === 'ok') {
    if (policy !== 'quarantine' && policy !== 'reject') {
      status = 'warn'
      reasons.push('health.reason.policyWeak')
    } else {
      reasons.push('health.reason.ok')
    }
  }

  return {
    ...stats,
    dmarcPolicy: policy,
    spfOk,
    dkimOk,
    status,
    reasons
  }
}
