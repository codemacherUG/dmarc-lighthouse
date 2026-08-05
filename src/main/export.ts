import type { AnalyzeResult, NamedBucket, ReportRow } from '../shared/types'
import { reportToAggregateXml, reportZipBasename } from './report-xml'
import { zipSingleFile } from './zip'

export function exportReportZip(report: ReportRow): { filename: string; data: Buffer } {
  const base = reportZipBasename(report)
  const xmlName = `${base}.xml`
  const xml = reportToAggregateXml(report)
  return {
    filename: `${base}.zip`,
    data: zipSingleFile(xmlName, xml)
  }
}

function csvEscape(value: string | number | null | undefined): string {
  const s = value == null ? '' : String(value)
  if (/[",\n\r]/.test(s)) return `"${s.replaceAll('"', '""')}"`
  return s
}

export function exportReportsJson(result: AnalyzeResult): string {
  return JSON.stringify(result, null, 2)
}

export function exportReportsCsv(result: AnalyzeResult): string {
  const lines: string[] = [
    [
      'reportId',
      'orgName',
      'domain',
      'dateBegin',
      'dateEnd',
      'total',
      'passing',
      'failing',
      'passRate',
      'policyP',
      'sourceIp',
      'count',
      'disposition',
      'dkimResult',
      'spfResult',
      'dmarc',
      'headerFrom',
      'reasons'
    ].join(',')
  ]

  for (const report of result.reports) {
    if (report.records.length === 0) {
      lines.push(
        [
          report.reportId,
          report.orgName,
          report.domain,
          report.dateBegin,
          report.dateEnd,
          report.total,
          report.passing,
          report.failing,
          report.passRate,
          report.policyP,
          '',
          '',
          '',
          '',
          '',
          '',
          '',
          ''
        ]
          .map(csvEscape)
          .join(',')
      )
      continue
    }

    for (const rec of report.records) {
      const reasons = (rec.reasons ?? [])
        .map((r) => [r.type, r.comment].filter(Boolean).join(': '))
        .filter(Boolean)
        .join(' | ')
      lines.push(
        [
          report.reportId,
          report.orgName,
          report.domain,
          report.dateBegin,
          report.dateEnd,
          report.total,
          report.passing,
          report.failing,
          report.passRate,
          report.policyP,
          rec.sourceIp,
          rec.count,
          rec.disposition,
          rec.dkimResult,
          rec.spfResult,
          rec.passesDmarc ? 'pass' : 'fail',
          rec.headerFrom,
          reasons
        ]
          .map(csvEscape)
          .join(',')
      )
    }
  }

  if ((result.forensicReports ?? []).length > 0) {
    lines.push('')
    lines.push(
      [
        'forensicId',
        'arrivalDate',
        'reportedDomain',
        'sourceIp',
        'authFailure',
        'envelopeFrom',
        'headerFrom',
        'feedbackType',
        'deliveryResult'
      ].join(',')
    )
    for (const f of result.forensicReports) {
      lines.push(
        [
          f.id,
          f.arrivalDate,
          f.reportedDomain,
          f.sourceIp,
          f.authFailure,
          f.envelopeFrom,
          f.headerFrom,
          f.feedbackType,
          f.deliveryResult
        ]
          .map(csvEscape)
          .join(',')
      )
    }
  }

  return lines.join('\n')
}

export function exportBucketsCsv(title: string, rows: NamedBucket[]): string {
  const lines = [`# ${title}`, 'name,count,passing,failing,passRate,label,provider']
  for (const r of rows) {
    lines.push(
      [r.name, r.count, r.passing, r.failing, r.passRate, r.label ?? '', r.provider ?? '']
        .map(csvEscape)
        .join(',')
    )
  }
  return lines.join('\n')
}
