import {
  DmarcParseError,
  decompressReport,
  parseDmarcXml,
  parseReportEmail,
  recordPassesDmarc,
  summarize,
  type DmarcReport
} from '@koduhai/dmarc-parser'
import { analyzeFromReports } from '../shared/analyze'
import type { AnalyzeResult, ReportRow, SerializedRecord } from '../shared/types'

function toIso(date: Date | null | undefined): string | null {
  if (!date) return null
  const t = date.getTime()
  if (Number.isNaN(t)) return null
  return date.toISOString()
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
    dkimSelectors: [
      ...new Set(
        (rec.dkimAuth ?? []).map((a) => a.selector?.trim()).filter((s): s is string => Boolean(s))
      )
    ],
    passesDmarc: recordPassesDmarc(rec),
    reasons: (rec.reasons ?? []).map((r) => ({ type: r.type, comment: r.comment }))
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

export { analyzeFromReports, applyDashboardFilter, buildDashboard } from '../shared/analyze'

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

  const rows = reports.map(serializeReport)
  return analyzeFromReports(rows, { skipped, errors: errors.slice(0, 50), newReports: rows.length })
}

export async function parseLocalBuffers(
  files: Array<{ name: string; data: Buffer }>
): Promise<AnalyzeResult> {
  const reports: DmarcReport[] = []
  const errors: string[] = []
  let skipped = 0

  for (const file of files) {
    try {
      const report = await parseLocalBuffer(file.name, file.data)
      reports.push(report)
    } catch (err) {
      skipped += 1
      const message =
        err instanceof DmarcParseError
          ? err.message
          : err instanceof Error
            ? err.message
            : String(err)
      errors.push(`${file.name}: ${message}`)
    }
  }

  const rows = reports.map(serializeReport)
  return analyzeFromReports(rows, { skipped, errors: errors.slice(0, 50), newReports: rows.length })
}

async function parseLocalBuffer(name: string, data: Buffer): Promise<DmarcReport> {
  const lower = name.toLowerCase()
  if (lower.endsWith('.eml') || lower.endsWith('.mime')) {
    return parseReportEmail(data)
  }
  if (lower.endsWith('.gz') || lower.endsWith('.zip')) {
    const xml = decompressReport(name, new Uint8Array(data))
    return parseDmarcXml(xml)
  }
  if (lower.endsWith('.xml')) {
    return parseDmarcXml(data.toString('utf8'))
  }

  const head = data.subarray(0, Math.min(data.length, 256)).toString('utf8')
  if (/^(return-path|received|from|mime-version|content-type):/im.test(head)) {
    return parseReportEmail(data)
  }
  if (data[0] === 0x1f && data[1] === 0x8b) {
    return parseDmarcXml(decompressReport(name || 'report.gz', new Uint8Array(data)))
  }
  if (data[0] === 0x50 && data[1] === 0x4b) {
    return parseDmarcXml(decompressReport(name || 'report.zip', new Uint8Array(data)))
  }
  return parseDmarcXml(data.toString('utf8'))
}
