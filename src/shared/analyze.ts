import type {
  AlignmentBreakdown,
  AnalyzeResult,
  DashboardData,
  DashboardFilter,
  DateRangePreset,
  DnsCheckResult,
  DomainHealth,
  DomainHealthStatus,
  DomainStats,
  ForensicReportRow,
  IpInfo,
  NamedBucket,
  ReportRow,
  SerializedRecord,
  VolumePoint
} from './types'
import { isLikelyGoogleIp } from './google-ip'
import { emptyAnalyzeResult, emptyDashboard } from './types'

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

/** Auth pattern of Google forwarding / report-echo noise (IP not checked). */
export function isGoogleNoiseAuthPattern(rec: SerializedRecord): boolean {
  if (!rec.passesDmarc) return false
  const spf = (rec.spfResult ?? '').toLowerCase()
  const dkim = (rec.dkimResult ?? '').toLowerCase()
  return spf === 'fail' && dkim === 'pass'
}

/**
 * Google-internal hop / report-echo noise: SPF fails on Google IP, DKIM holds, DMARC passes.
 * Uses enrichment labels when available, otherwise well-known Google IP prefixes.
 */
export function isGoogleNoiseRecord(
  rec: SerializedRecord,
  googleIps?: ReadonlySet<string>
): boolean {
  if (!isGoogleNoiseAuthPattern(rec)) return false
  if (googleIps?.has(rec.sourceIp)) return true
  return isLikelyGoogleIp(rec.sourceIp)
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
  map: Map<string, { count: number; passing: number; failing: number }>,
  name: string,
  count: number,
  passes: boolean
): void {
  const key = name || '(unbekannt)'
  const cur = map.get(key) ?? { count: 0, passing: 0, failing: 0 }
  cur.count += count
  if (passes) cur.passing += count
  else cur.failing += count
  map.set(key, cur)
}

function toNamedBuckets(
  map: Map<string, { count: number; passing: number; failing: number }>,
  limit = 25
): NamedBucket[] {
  return [...map.entries()]
    .map(([name, v]) => ({
      name,
      count: v.count,
      passing: v.passing,
      failing: v.failing,
      passRate: v.count ? Math.round((v.passing / v.count) * 1000) / 10 : 0
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit)
}

export function buildDashboard(reports: ReportRow[]): DashboardData {
  if (reports.length === 0) return emptyDashboard()

  const dmarc: AlignmentBreakdown = { pass: 0, fail: 0, other: 0 }
  const spf: AlignmentBreakdown = { pass: 0, fail: 0, other: 0 }
  const dkim: AlignmentBreakdown = { pass: 0, fail: 0, other: 0 }
  const dispositionMap = new Map<string, { count: number; passing: number; failing: number }>()
  const byOrg = new Map<string, { count: number; passing: number; failing: number }>()
  const bySourceIp = new Map<string, { count: number; passing: number; failing: number }>()
  const byHeaderFrom = new Map<string, { count: number; passing: number; failing: number }>()
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
      bumpNamed(dispositionMap, rec.disposition ?? 'none', n, rec.passesDmarc)
      bumpNamed(byOrg, report.orgName, n, rec.passesDmarc)
      bumpNamed(bySourceIp, rec.sourceIp, n, rec.passesDmarc)
      bumpNamed(byHeaderFrom, rec.headerFrom ?? '(unbekannt)', n, rec.passesDmarc)
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
    volumeByDay: [...volumeMap.values()].sort((a, b) => a.date.localeCompare(b.date))
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
  const rows = [...reports].sort((a, b) => b.dateEnd.localeCompare(a.dateEnd))
  const forensicReports = [...(extras?.forensicReports ?? [])].sort((a, b) =>
    (b.arrivalDate ?? '').localeCompare(a.arrivalDate ?? '')
  )
  if (rows.length === 0) {
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

  for (const r of rows) {
    total += r.total
    passing += r.passing
    failing += r.failing
    if (r.domain) domains.add(r.domain)
    if (r.dateBegin && (!dateBegin || r.dateBegin < dateBegin)) dateBegin = r.dateBegin
    if (r.dateEnd && (!dateEnd || r.dateEnd > dateEnd)) dateEnd = r.dateEnd
  }

  return {
    aggregate: {
      reportCount: rows.length,
      total,
      passing,
      failing,
      passRate: total ? Math.round((passing / total) * 1000) / 10 : 0,
      dateBegin,
      dateEnd,
      domains: [...domains].sort()
    },
    dashboard: buildDashboard(rows),
    reports: rows,
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

function parseDay(value: string | undefined, endOfDay: boolean): number | null {
  if (!value) return null
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return null
  if (endOfDay) d.setHours(23, 59, 59, 999)
  else d.setHours(0, 0, 0, 0)
  return d.getTime()
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
  const customFrom = filter.range === 'custom' ? parseDay(filter.from, false) : null
  const customTo = filter.range === 'custom' ? parseDay(filter.to, true) : null
  const domain = filter.domain.trim().toLowerCase()
  const org = filter.org?.trim()
  const sourceIp = filter.sourceIp?.trim()
  const headerFrom = filter.headerFrom?.trim()
  const hideGoogleNoise = Boolean(filter.hideGoogleNoise)
  const googleIps = filter.googleIps

  const rows: ReportRow[] = []
  for (const r of reports) {
    if (domain && r.domain.toLowerCase() !== domain) continue
    if (org && (r.orgName || UNKNOWN) !== org) continue

    const end = r.dateEnd || r.dateBegin
    if (cutoff || customFrom != null || customTo != null) {
      if (!end) continue
      const t = new Date(end).getTime()
      if (Number.isNaN(t)) continue
      if (cutoff && t < cutoff.getTime()) continue
      if (customFrom != null && t < customFrom) continue
      if (customTo != null && t > customTo) continue
    }

    if (sourceIp || headerFrom || hideGoogleNoise) {
      const records = r.records.filter((rec) => {
        if (sourceIp && rec.sourceIp !== sourceIp) return false
        if (headerFrom && (rec.headerFrom ?? UNKNOWN) !== headerFrom) return false
        if (hideGoogleNoise && isGoogleNoiseRecord(rec, googleIps)) return false
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
  const customFrom = filter.range === 'custom' ? parseDay(filter.from, false) : null
  const customTo = filter.range === 'custom' ? parseDay(filter.to, true) : null
  const domain = filter.domain.trim().toLowerCase()
  const sourceIp = filter.sourceIp?.trim()
  const headerFrom = filter.headerFrom?.trim()

  return reports.filter((r) => {
    if (domain && (r.reportedDomain ?? '').toLowerCase() !== domain) return false
    if (sourceIp && r.sourceIp !== sourceIp) return false
    if (headerFrom && (r.headerFrom ?? UNKNOWN) !== headerFrom) return false
    const end = r.arrivalDate
    if (cutoff || customFrom != null || customTo != null) {
      if (!end) return false
      const t = new Date(end).getTime()
      if (Number.isNaN(t)) return false
      if (cutoff && t < cutoff.getTime()) return false
      if (customFrom != null && t < customFrom) return false
      if (customTo != null && t > customTo) return false
    }
    return true
  })
}

export function applyDashboardFilter(full: AnalyzeResult, filter: DashboardFilter): AnalyzeResult {
  const filtered = filterReports(full.reports, filter)
  return analyzeFromReports(filtered, {
    skipped: full.skipped,
    errors: full.errors,
    fromCache: full.fromCache,
    newReports: full.newReports,
    newForensicReports: full.newForensicReports,
    forensicReports: filterForensicReports(full.forensicReports ?? [], filter)
  })
}

/** Aggregate volume / selectors per report domain. */
export function buildDomainStats(reports: ReportRow[]): DomainStats[] {
  const map = new Map<
    string,
    { total: number; passing: number; failing: number; selectors: Set<string> }
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
    cur.total += r.total
    cur.passing += r.passing
    cur.failing += r.failing
    for (const rec of r.records) {
      for (const sel of rec.dkimSelectors ?? []) {
        if (sel) cur.selectors.add(sel)
      }
    }
    map.set(domain, cur)
  }
  return [...map.entries()]
    .map(([domain, v]) => ({
      domain,
      total: v.total,
      passing: v.passing,
      failing: v.failing,
      passRate: v.total ? Math.round((v.passing / v.total) * 1000) / 10 : 0,
      dkimSelectors: [...v.selectors].sort()
    }))
    .sort((a, b) => b.total - a.total)
}

/**
 * Merge report stats with a DNS check into Ampel status.
 * Rules:
 * - bad: no DMARC, or pass rate &lt; 90%, or no SPF
 * - warn: p=none, or pass rate 90–98%, or DKIM selectors missing in DNS
 * - ok: quarantine/reject, SPF ok, pass rate ≥ 98%
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
  if (stats.passRate < 90) {
    status = 'bad'
    reasons.push('health.reason.lowPassRate')
  }

  if (status !== 'bad') {
    if (policy === 'none') {
      status = 'warn'
      reasons.push('health.reason.policyNone')
    }
    if (stats.passRate < 98) {
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
