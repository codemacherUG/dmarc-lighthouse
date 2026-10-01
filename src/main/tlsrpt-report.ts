import { createHash } from 'node:crypto'
import { gunzipSync } from 'node:zlib'
import { simpleParser } from 'mailparser'
import type { TlsRptFailureDetailRow, TlsRptPolicyRow, TlsRptReportRow } from '../shared/types'

const MAX_COMPRESSED_BYTES = 10 * 1024 * 1024
const MAX_REPORT_BYTES = 25 * 1024 * 1024

function object(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null
}

function text(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim() : null
}

function count(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null
}

function strings(value: unknown): string[] {
  const values = Array.isArray(value) ? value : value == null ? [] : [value]
  return values
    .filter((item): item is string => typeof item === 'string')
    .map((item) => item.trim())
}

function isoDate(value: unknown): string | null {
  const date = typeof value === 'string' ? new Date(value) : null
  return date && Number.isFinite(date.getTime()) ? date.toISOString() : null
}

function parseFailureDetail(value: unknown): TlsRptFailureDetailRow | null {
  const detail = object(value)
  if (!detail) return null
  const resultType = text(detail['result-type'])
  const failedSessionCount = count(detail['failed-session-count'])
  if (!resultType || failedSessionCount == null) return null
  return {
    resultType,
    sendingMtaIp: text(detail['sending-mta-ip']),
    receivingMxHostname: text(detail['receiving-mx-hostname']),
    receivingIp: text(detail['receiving-ip']),
    failedSessionCount,
    additionalInformation: text(detail['additional-information']),
    failureReasonCode: text(detail['failure-reason-code'])
  }
}

function parsePolicy(value: unknown): TlsRptPolicyRow | null {
  const row = object(value)
  const policy = object(row?.policy)
  const summary = object(row?.summary)
  if (!row || !policy || !summary) return null
  const policyType = text(policy['policy-type'])
  const policyDomain = text(policy['policy-domain'])
  const successfulSessions = count(summary['total-successful-session-count'])
  const failedSessions = count(summary['total-failure-session-count'])
  if (!policyType || !policyDomain || successfulSessions == null || failedSessions == null)
    return null

  const rawDetails = row['failure-details'] ?? []
  if (!Array.isArray(rawDetails)) return null
  const failureDetails = rawDetails.map(parseFailureDetail)
  if (failureDetails.some((detail) => detail == null)) return null
  return {
    policyType,
    policyString: strings(policy['policy-string']),
    policyDomain,
    mxHosts: strings(policy['mx-host']),
    successfulSessions,
    failedSessions,
    failureDetails: failureDetails as TlsRptFailureDetailRow[]
  }
}

export function parseTlsRptJson(value: Buffer | string): TlsRptReportRow | null {
  let raw: unknown
  try {
    raw = JSON.parse(typeof value === 'string' ? value : value.toString('utf8'))
  } catch {
    return null
  }
  const report = object(raw)
  const dateRange = object(report?.['date-range'])
  if (!report || !dateRange || !Array.isArray(report.policies)) return null
  const orgName = text(report['organization-name'])
  const reportId = text(report['report-id'])
  const dateBegin = isoDate(dateRange['start-datetime'])
  const dateEnd = isoDate(dateRange['end-datetime'])
  const policies = report.policies.map(parsePolicy)
  if (!orgName || !reportId || !dateBegin || !dateEnd || policies.length === 0) return null
  if (policies.some((policy) => policy == null)) return null

  const validPolicies = policies as TlsRptPolicyRow[]
  const identity = createHash('sha256')
    .update([orgName, reportId, dateBegin].join('\0'))
    .digest('hex')
  return {
    id: identity,
    reportId,
    orgName,
    dateBegin,
    dateEnd,
    successfulSessions: validPolicies.reduce(
      (total, policy) => total + policy.successfulSessions,
      0
    ),
    failedSessions: validPolicies.reduce((total, policy) => total + policy.failedSessions, 0),
    policies: validPolicies
  }
}

function decodeAttachment(content: Buffer): Buffer | null {
  if (content[0] === 0x1f && content[1] === 0x8b) {
    if (content.length > MAX_COMPRESSED_BYTES) return null
    try {
      return gunzipSync(content, { maxOutputLength: MAX_REPORT_BYTES })
    } catch {
      return null
    }
  }
  return content.length <= MAX_REPORT_BYTES ? content : null
}

export async function parseTlsRptMime(source: Buffer): Promise<TlsRptReportRow[]> {
  const candidate = source.toString('latin1').toLowerCase()
  if (!candidate.includes('tlsrpt') && !candidate.includes('report domain:')) return []
  const message = await simpleParser(source)
  const reports: TlsRptReportRow[] = []
  for (const attachment of message.attachments) {
    const content = decodeAttachment(attachment.content)
    if (!content) continue
    const report = parseTlsRptJson(content)
    if (report) reports.push(report)
  }
  return reports
}

export async function parseTlsRptFile(name: string, data: Buffer): Promise<TlsRptReportRow[]> {
  const lower = name.toLowerCase()
  if (lower.endsWith('.eml') || lower.endsWith('.mime')) return parseTlsRptMime(data)
  const content = decodeAttachment(data)
  if (!content) return []
  const report = parseTlsRptJson(content)
  return report ? [report] : []
}
