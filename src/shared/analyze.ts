import type {
  AlignmentBreakdown,
  AnalyzeResult,
  DashboardData,
  DashboardFilter,
  DateRangePreset,
  NamedBucket,
  ReportRow,
  VolumePoint
} from './types'
import { emptyAnalyzeResult, emptyDashboard } from './types'

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
  extras?: { skipped?: number; errors?: string[]; fromCache?: boolean; newReports?: number }
): AnalyzeResult {
  const rows = [...reports].sort((a, b) => b.dateEnd.localeCompare(a.dateEnd))
  if (rows.length === 0) {
    return {
      ...emptyAnalyzeResult(),
      skipped: extras?.skipped ?? 0,
      errors: extras?.errors ?? [],
      fromCache: extras?.fromCache,
      newReports: extras?.newReports ?? 0
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
    skipped: extras?.skipped ?? 0,
    errors: extras?.errors ?? [],
    fromCache: extras?.fromCache,
    newReports: extras?.newReports
  }
}

function rangeCutoff(range: DateRangePreset): Date | null {
  if (range === 'all') return null
  const days = Number(range)
  if (!Number.isFinite(days) || days <= 0) return null
  const d = new Date()
  d.setHours(0, 0, 0, 0)
  d.setDate(d.getDate() - days)
  return d
}

export function filterReports(reports: ReportRow[], filter: DashboardFilter): ReportRow[] {
  const cutoff = rangeCutoff(filter.range)
  const domain = filter.domain.trim().toLowerCase()

  return reports.filter((r) => {
    if (domain && r.domain.toLowerCase() !== domain) return false
    if (cutoff) {
      const end = r.dateEnd || r.dateBegin
      if (!end) return false
      const t = new Date(end).getTime()
      if (Number.isNaN(t) || t < cutoff.getTime()) return false
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
    newReports: full.newReports
  })
}
