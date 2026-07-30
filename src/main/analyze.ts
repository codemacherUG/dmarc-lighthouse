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
import type { AnalyzeResult, ForensicReportRow, ReportRow, SerializedRecord } from '../shared/types'
import { ForensicParseError, isLikelyForensicMime, parseForensicEmail } from './forensic'

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

type ParsedMime =
  | { kind: 'aggregate'; report: DmarcReport }
  | { kind: 'forensic'; report: ForensicReportRow }

async function parseMimeBuffer(source: Buffer): Promise<ParsedMime> {
  if (isLikelyForensicMime(source)) {
    try {
      return { kind: 'forensic', report: parseForensicEmail(source) }
    } catch {
      // Fall through to aggregate parsing.
    }
  }
  try {
    const report = await parseReportEmail(source)
    return { kind: 'aggregate', report }
  } catch (aggErr) {
    try {
      return { kind: 'forensic', report: parseForensicEmail(source) }
    } catch {
      throw aggErr
    }
  }
}

export async function parseMimeSources(
  sources: Array<{ uid: number; source: Buffer }>
): Promise<AnalyzeResult> {
  const reports: DmarcReport[] = []
  const forensicReports: ForensicReportRow[] = []
  const errors: string[] = []
  let skipped = 0

  for (const item of sources) {
    try {
      const parsed = await parseMimeBuffer(item.source)
      if (parsed.kind === 'aggregate') reports.push(parsed.report)
      else forensicReports.push(parsed.report)
    } catch (err) {
      skipped += 1
      const message =
        err instanceof DmarcParseError || err instanceof ForensicParseError
          ? err.message
          : err instanceof Error
            ? err.message
            : String(err)
      errors.push(`UID ${item.uid}: ${message}`)
    }
  }

  const rows = reports.map(serializeReport)
  return analyzeFromReports(rows, {
    skipped,
    errors: errors.slice(0, 50),
    newReports: rows.length,
    newForensicReports: forensicReports.length,
    forensicReports
  })
}

export async function parseLocalBuffers(
  files: Array<{ name: string; data: Buffer }>
): Promise<AnalyzeResult> {
  const reports: DmarcReport[] = []
  const forensicReports: ForensicReportRow[] = []
  const errors: string[] = []
  let skipped = 0

  for (const file of files) {
    try {
      const parsed = await parseLocalBuffer(file.name, file.data)
      if (parsed.kind === 'aggregate') reports.push(parsed.report)
      else forensicReports.push(parsed.report)
    } catch (err) {
      skipped += 1
      const message =
        err instanceof DmarcParseError || err instanceof ForensicParseError
          ? err.message
          : err instanceof Error
            ? err.message
            : String(err)
      errors.push(`${file.name}: ${message}`)
    }
  }

  const rows = reports.map(serializeReport)
  return analyzeFromReports(rows, {
    skipped,
    errors: errors.slice(0, 50),
    newReports: rows.length,
    newForensicReports: forensicReports.length,
    forensicReports
  })
}

async function parseLocalBuffer(name: string, data: Buffer): Promise<ParsedMime> {
  const lower = name.toLowerCase()
  if (lower.endsWith('.eml') || lower.endsWith('.mime')) {
    return parseMimeBuffer(data)
  }
  if (lower.endsWith('.gz') || lower.endsWith('.zip')) {
    const xml = decompressReport(name, new Uint8Array(data))
    return { kind: 'aggregate', report: parseDmarcXml(xml) }
  }
  if (lower.endsWith('.xml')) {
    return { kind: 'aggregate', report: parseDmarcXml(data.toString('utf8')) }
  }
  // Heuristic for extension-less payloads.
  const head = data.subarray(0, Math.min(data.length, 256))
  if (head[0] === 0x1f && head[1] === 0x8b) {
    const xml = decompressReport(`${name}.gz`, new Uint8Array(data))
    return { kind: 'aggregate', report: parseDmarcXml(xml) }
  }
  if (head[0] === 0x50 && head[1] === 0x4b) {
    const xml = decompressReport(`${name}.zip`, new Uint8Array(data))
    return { kind: 'aggregate', report: parseDmarcXml(xml) }
  }
  const asText = data.toString('utf8', 0, Math.min(data.length, 512)).toLowerCase()
  if (asText.includes('content-type:') || asText.includes('mime-version:')) {
    return parseMimeBuffer(data)
  }
  return { kind: 'aggregate', report: parseDmarcXml(data.toString('utf8')) }
}
