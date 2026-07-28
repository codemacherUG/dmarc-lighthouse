import type { AnalyzeResult, NamedBucket } from '../shared/types'

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
