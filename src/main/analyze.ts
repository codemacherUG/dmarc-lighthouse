import {
  aggregate,
  DmarcParseError,
  parseReportEmail,
  recordPassesDmarc,
  summarize,
  type DmarcReport
} from '@koduhai/dmarc-parser'
import type {
  AlignmentBreakdown,
  AnalyzeResult,
  DashboardData,
  NamedBucket,
  ReportRow,
  SerializedRecord,
  VolumePoint
} from '../shared/types'
import { emptyDashboard } from '../shared/types'

function toIso(date: Date | null | undefined): string | null {
  if (!date) return null
  const t = date.getTime()
  if (Number.isNaN(t)) return null
  return date.toISOString()
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

function buildDashboard(reports: ReportRow[]): DashboardData {
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
    const vol = volumeMap.get(day) ?? { date: day, total: 0, passing: 0, failing: 0 }
    vol.total += report.total
    vol.passing += report.passing
    vol.failing += report.failing
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

function serializeReport(report: DmarcReport): ReportRow {
  const summary = summarize(report)
  const records: SerializedRecord[] = report.records.map((rec) => ({
    sourceIp: rec.sourceIp,
    count: rec.count,
    disposition: rec.disposition,
    dkimResult: rec.dkimResult,
    spfResult: rec.spfResult,
    headerFrom: rec.headerFrom,
    dkimDomain: rec.dkimDomain,
    spfDomain: rec.spfDomain,
    passesDmarc: recordPassesDmarc(rec)
  }))

  return {
    reportId: report.meta.reportId,
    orgName: report.meta.orgName,
    domain: report.meta.domain,
    dateBegin: toIso(report.meta.dateBegin) ?? '',
    dateEnd: toIso(report.meta.dateEnd) ?? '',
    total: summary.total,
    passing: summary.passing,
    failing: summary.failing,
    passRate: summary.passRate,
    policyP: report.meta.policyP,
    records
  }
}

export async function parseMimeSources(
  sources: Array<{ uid: number; source: Buffer }>
): Promise<AnalyzeResult> {
  const reports: DmarcReport[] = []
  const errors: string[] = []
  let skipped = 0

  for (const item of sources) {
    try {
      const report = await parseReportEmail(item.source)
      reports.push(report)
    } catch (err) {
      skipped += 1
      const message =
        err instanceof DmarcParseError
          ? err.message
          : err instanceof Error
            ? err.message
            : String(err)
      errors.push(`UID ${item.uid}: ${message}`)
    }
  }

  const agg = aggregate(reports)
  const rows = reports.map(serializeReport).sort((a, b) => b.dateEnd.localeCompare(a.dateEnd))

  return {
    aggregate: {
      reportCount: agg.reportCount,
      total: agg.total,
      passing: agg.passing,
      failing: agg.failing,
      passRate: agg.passRate,
      dateBegin: toIso(agg.dateBegin),
      dateEnd: toIso(agg.dateEnd),
      domains: agg.domains
    },
    dashboard: buildDashboard(rows),
    reports: rows,
    skipped,
    errors: errors.slice(0, 50)
  }
}
