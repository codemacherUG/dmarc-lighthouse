import type { ReportRow, SerializedRecord } from '../shared/types'

function xmlEscape(value: string | null | undefined): string {
  if (value == null) return ''
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;')
}

function toUnix(iso: string): number {
  if (!iso) return 0
  if (/^\d+$/.test(iso)) return Number(iso)
  const ms = Date.parse(iso)
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : 0
}

function recordXml(rec: SerializedRecord): string {
  const reasons = (rec.reasons ?? [])
    .map(
      (r) => `        <reason>
          <type>${xmlEscape(r.type)}</type>
          <comment>${xmlEscape(r.comment)}</comment>
        </reason>`
    )
    .join('\n')

  const selectors =
    rec.dkimSelectors.length > 0 ? rec.dkimSelectors : rec.dkimDomain || rec.dkimResult ? [''] : []

  const dkimBlocks = selectors
    .map((selector) => {
      const sel = selector
        ? `\n          <selector>${xmlEscape(selector)}</selector>`
        : ''
      return `        <dkim>
          <domain>${xmlEscape(rec.dkimDomain)}</domain>${sel}
          <result>${xmlEscape(rec.dkimRawResult)}</result>
        </dkim>`
    })
    .join('\n')

  const spfBlock =
    rec.spfDomain || rec.spfResult
      ? `        <spf>
          <domain>${xmlEscape(rec.spfDomain)}</domain>
          <result>${xmlEscape(rec.spfRawResult)}</result>
        </spf>`
      : ''

  return `  <record>
    <row>
      <source_ip>${xmlEscape(rec.sourceIp)}</source_ip>
      <count>${rec.count}</count>
      <policy_evaluated>
        <disposition>${xmlEscape(rec.disposition)}</disposition>
        <dkim>${xmlEscape(rec.dkimResult)}</dkim>
        <spf>${xmlEscape(rec.spfResult)}</spf>
${reasons}
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>${xmlEscape(rec.headerFrom)}</header_from>
    </identifiers>
    <auth_results>
${dkimBlocks}
${spfBlock}
    </auth_results>
  </record>`
}

/**
 * Rebuild a DMARC aggregate feedback XML from cached ReportRow data.
 * Not bit-identical to the original attachment (email, some policy fields may be missing).
 */
export function reportToAggregateXml(report: ReportRow): string {
  const begin = toUnix(report.dateBegin)
  const end = toUnix(report.dateEnd)
  const records = report.records.map(recordXml).join('\n')

  return `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <version>1.0</version>
  <report_metadata>
    <org_name>${xmlEscape(report.orgName)}</org_name>
    <email></email>
    <report_id>${xmlEscape(report.reportId)}</report_id>
    <date_range>
      <begin>${begin}</begin>
      <end>${end}</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>${xmlEscape(report.domain)}</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>${xmlEscape(report.policyP)}</p>
    <sp>${xmlEscape(report.policyP)}</sp>
    <pct>100</pct>
  </policy_published>
${records}
</feedback>
`
}

/** Safe basename fragment for ZIP / XML filenames. */
export function sanitizeReportFilenamePart(value: string): string {
  return value
    .trim()
    .replace(/[^\w.-]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 80) || 'report'
}

export function reportZipBasename(report: ReportRow): string {
  const domain = sanitizeReportFilenamePart(report.domain)
  const id = sanitizeReportFilenamePart(report.reportId)
  const begin = toUnix(report.dateBegin)
  const end = toUnix(report.dateEnd)
  return `${domain}!${id}!${begin}!${end}`
}
