import { createHash } from 'crypto'
import type { ForensicReportRow } from '../shared/types'

export class ForensicParseError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ForensicParseError'
  }
}

function normalizeHeaderKey(key: string): string {
  return key.trim().toLowerCase()
}

/** Unfold and parse simple RFC 5322 header blocks into a map. */
export function parseHeaderBlock(raw: string): Map<string, string> {
  const unfolded = raw.replace(/\r\n[ \t]+/g, ' ').replace(/\n[ \t]+/g, ' ')
  const map = new Map<string, string>()
  for (const line of unfolded.split(/\r?\n/)) {
    const idx = line.indexOf(':')
    if (idx <= 0) continue
    const key = normalizeHeaderKey(line.slice(0, idx))
    const value = line.slice(idx + 1).trim()
    if (!key) continue
    const prev = map.get(key)
    map.set(key, prev ? `${prev} ${value}` : value)
  }
  return map
}

function header(map: Map<string, string>, ...names: string[]): string | null {
  for (const name of names) {
    const v = map.get(normalizeHeaderKey(name))
    if (v) return v
  }
  return null
}

function extractAddress(value: string | null): string | null {
  if (!value) return null
  const angle = value.match(/<([^>]+)>/)
  if (angle?.[1]) return angle[1].trim()
  const plain = value.trim()
  return plain || null
}

function extractBoundary(contentType: string | null): string | null {
  if (!contentType) return null
  const m = contentType.match(/boundary=(?:"([^"]+)"|([^;\s]+))/i)
  return m?.[1] ?? m?.[2] ?? null
}

function splitMultipart(body: string, boundary: string): Array<{ headers: string; body: string }> {
  const delim = `--${boundary}`
  const parts = body.split(delim)
  const out: Array<{ headers: string; body: string }> = []
  for (const part of parts) {
    const trimmed = part
      .replace(/^\r?\n/, '')
      .replace(/--\s*$/, '')
      .trim()
    if (!trimmed || trimmed === '--') continue
    const splitAt = trimmed.search(/\r?\n\r?\n/)
    if (splitAt < 0) {
      out.push({ headers: trimmed, body: '' })
      continue
    }
    out.push({
      headers: trimmed.slice(0, splitAt),
      body: trimmed
        .slice(splitAt)
        .replace(/^\r?\n\r?\n/, '')
        .replace(/^\n\n/, '')
    })
  }
  return out
}

function looksLikeFeedbackReport(headers: Map<string, string>, body: string): boolean {
  const ct = header(headers, 'content-type')?.toLowerCase() ?? ''
  if (ct.includes('multipart/report') && ct.includes('feedback-report')) return true
  if (ct.includes('message/feedback-report')) return true
  if (/^Feedback-Type:/im.test(body) || /^Auth-Failure:/im.test(body)) return true
  return false
}

function parseFeedbackFields(text: string): Map<string, string> {
  return parseHeaderBlock(text)
}

function stableForensicId(fields: {
  sourceIp: string | null
  arrivalDate: string | null
  envelopeFrom: string | null
  headerFrom: string | null
  reportedDomain: string | null
  subject: string | null
  authFailure: string | null
}): string {
  const raw = [
    fields.sourceIp ?? '',
    fields.arrivalDate ?? '',
    fields.envelopeFrom ?? '',
    fields.headerFrom ?? '',
    fields.reportedDomain ?? '',
    fields.subject ?? '',
    fields.authFailure ?? ''
  ].join('|')
  return createHash('sha256').update(raw).digest('hex').slice(0, 24)
}

function toIsoMaybe(value: string | null): string | null {
  if (!value) return null
  const t = Date.parse(value)
  if (Number.isNaN(t)) return value
  return new Date(t).toISOString()
}

function buildRow(input: {
  feedback: Map<string, string>
  originalHeaders: Map<string, string>
  topHeaders: Map<string, string>
  orgHint?: string | null
}): ForensicReportRow {
  const f = input.feedback
  const o = input.originalHeaders
  const sourceIp = header(f, 'Source-IP', 'Source-Ip')
  const arrivalDate = toIsoMaybe(header(f, 'Arrival-Date', 'Received-Date'))
  const envelopeFrom = extractAddress(
    header(f, 'Original-Mail-From', 'Mail-From') ?? header(o, 'Return-Path', 'From')
  )
  const headerFrom = extractAddress(header(o, 'From') ?? header(f, 'From'))
  const reportedDomain = header(f, 'Reported-Domain', 'DKIM-Domain')
  const subject = header(o, 'Subject') ?? header(input.topHeaders, 'Subject')
  const authFailure = header(f, 'Auth-Failure', 'Authentication-Failure')
  const rowBase = {
    sourceIp,
    arrivalDate,
    envelopeFrom,
    headerFrom,
    reportedDomain,
    subject,
    authFailure
  }
  return {
    id: stableForensicId(rowBase),
    reportId: header(f, 'Feedback-ID', 'Report-ID'),
    orgName: input.orgHint ?? extractAddress(header(input.topHeaders, 'From')),
    reportedDomain,
    arrivalDate,
    sourceIp,
    authFailure,
    deliveryResult: header(f, 'Delivery-Result'),
    envelopeFrom,
    headerFrom,
    originalRcptTo: extractAddress(header(f, 'Original-Rcpt-To', 'Original-Rcpt-to')),
    authenticationResults: header(f, 'Authentication-Results'),
    subject,
    feedbackType: header(f, 'Feedback-Type')
  }
}

/**
 * Parse a DMARC failure / forensic (RUF) email in ARF form
 * (`multipart/report; report-type=feedback-report`).
 * Only sanitized headers are kept — no message bodies.
 */
export function parseForensicEmail(source: Buffer | string): ForensicReportRow {
  const text = typeof source === 'string' ? source : source.toString('utf8')
  const splitAt = text.search(/\r?\n\r?\n/)
  if (splitAt < 0) throw new ForensicParseError('Missing header/body separator')
  const topHeaders = parseHeaderBlock(text.slice(0, splitAt))
  const body = text
    .slice(splitAt)
    .replace(/^\r?\n\r?\n/, '')
    .replace(/^\n\n/, '')

  if (!looksLikeFeedbackReport(topHeaders, body)) {
    throw new ForensicParseError('Not an ARF/feedback forensic report')
  }

  const contentType = header(topHeaders, 'content-type')
  const boundary = extractBoundary(contentType)
  let feedback = new Map<string, string>()
  let originalHeaders = new Map<string, string>()

  if (boundary) {
    const parts = splitMultipart(body, boundary)
    for (const part of parts) {
      const ph = parseHeaderBlock(part.headers)
      const pct = (header(ph, 'content-type') ?? '').toLowerCase()
      if (pct.includes('message/feedback-report') || pct.includes('text/plain')) {
        const fields = parseFeedbackFields(part.body)
        if (fields.has('feedback-type') || fields.has('auth-failure') || fields.has('source-ip')) {
          feedback = fields
        }
      }
      if (
        pct.includes('text/rfc822-headers') ||
        pct.includes('message/rfc822-headers') ||
        pct.includes('message/rfc822')
      ) {
        // Prefer headers-only parts; for message/rfc822 take the nested headers.
        const nestedSplit = part.body.search(/\r?\n\r?\n/)
        const headerText = nestedSplit >= 0 ? part.body.slice(0, nestedSplit) : part.body
        const parsed = parseHeaderBlock(headerText)
        if (parsed.size > 0) originalHeaders = parsed
      }
    }
  } else {
    feedback = parseFeedbackFields(body)
  }

  if (
    !feedback.has('feedback-type') &&
    !feedback.has('auth-failure') &&
    !feedback.has('source-ip')
  ) {
    throw new ForensicParseError('No forensic feedback fields found')
  }

  return buildRow({ feedback, originalHeaders, topHeaders })
}

export function isLikelyForensicMime(source: Buffer | string): boolean {
  const sample = (
    typeof source === 'string' ? source : source.toString('utf8', 0, 4096)
  ).toLowerCase()
  return (
    sample.includes('report-type=feedback-report') ||
    sample.includes('message/feedback-report') ||
    sample.includes('\nauth-failure:') ||
    sample.includes('\r\nauth-failure:')
  )
}
