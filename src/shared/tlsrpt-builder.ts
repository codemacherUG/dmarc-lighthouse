import { isValidDomain, normalizeDomain } from './dmarc-builder'
import { parseTlsRptRecord } from './transport'

export type TlsRptBuilderStep = 'domain' | 'reporting' | 'result'

export const TLSRPT_BUILDER_STEPS: TlsRptBuilderStep[] = ['domain', 'reporting', 'result']

export interface TlsRptBuilderInput {
  domain: string
  /** Report targets (email, mailto:, or https:), comma/space separated. */
  rua: string
}

export interface TlsRptTag {
  key: string
  value: string
}

export interface TlsRptRecordResult {
  domain: string
  host: string
  type: 'TXT'
  value: string
  tags: TlsRptTag[]
}

export const DEFAULT_TLSRPT_BUILDER_INPUT: TlsRptBuilderInput = {
  domain: '',
  rua: ''
}

export function tlsrptStepIndex(step: TlsRptBuilderStep): number {
  return TLSRPT_BUILDER_STEPS.indexOf(step)
}

/** Suggested mailbox for rua= (RFC 8460). */
export function defaultTlsRptMailbox(domain: string): string {
  const d = normalizeDomain(domain)
  return d ? `tlsrpt@${d}` : ''
}

function splitAddresses(raw: string): string[] {
  return [
    ...new Set(
      raw
        .split(/[,;\s]+/)
        .map((s) => s.trim())
        .filter(Boolean)
    )
  ]
}

/** RFC 8460: rua URIs must be mailto: or https:. */
export function normalizeTlsRptUri(raw: string): string | null {
  const value = raw.trim()
  if (!value) return null
  if (/^https:/i.test(value)) return value
  if (/^https?:/i.test(value)) return null
  const addr = value.replace(/^mailto:/i, '').trim()
  if (!addr || !/^[^\s@]+@[^\s@]+$/i.test(addr)) return null
  return `mailto:${addr}`
}

export function parseTlsRptUris(raw: string): string[] {
  return splitAddresses(raw)
    .map(normalizeTlsRptUri)
    .filter((uri): uri is string => Boolean(uri))
}

export function buildTlsRptRecord(input: TlsRptBuilderInput): TlsRptRecordResult {
  const domain = normalizeDomain(input.domain)
  const rua = parseTlsRptUris(input.rua)
  const tags: TlsRptTag[] = [{ key: 'v', value: 'TLSRPTv1' }]
  if (rua.length > 0) {
    tags.push({ key: 'rua', value: rua.join(',') })
  }
  return {
    domain,
    host: domain ? `_smtp._tls.${domain}` : '_smtp._tls',
    type: 'TXT',
    value: tags.map((t) => `${t.key}=${t.value}`).join('; '),
    tags
  }
}

/** Prefill builder fields from an existing TLS-RPT TXT record. */
export function parseTlsRptBuilderRecord(record: string): Partial<TlsRptBuilderInput> {
  const parsed = parseTlsRptRecord([record])
  if (!parsed.found) return {}
  return {
    rua: parsed.rua.map((s) => s.replace(/^mailto:/i, '')).join(', ')
  }
}

export function tlsrptRecordsEquivalent(a: string, b: string): boolean {
  const left = parseTlsRptRecord([a])
  const right = parseTlsRptRecord([b])
  if (!left.found || !right.found) {
    return a.replace(/\s+/g, '') === b.replace(/\s+/g, '')
  }
  if (left.rua.length !== right.rua.length) return false
  const sort = (list: string[]): string[] => [...list].map((s) => s.toLowerCase()).sort()
  return sort(left.rua).every((uri, i) => uri === sort(right.rua)[i])
}

export function validateTlsRptBuilderStep(
  step: TlsRptBuilderStep,
  input: TlsRptBuilderInput
): string | null {
  if (step === 'domain' || step === 'result') {
    if (!isValidDomain(input.domain)) return 'tlsrptBuilder.error.domain'
  }
  if (step === 'reporting' || step === 'result') {
    const tokens = splitAddresses(input.rua)
    if (tokens.length === 0) return 'tlsrptBuilder.error.rua'
    if (tokens.some((token) => !normalizeTlsRptUri(token))) return 'tlsrptBuilder.error.ruaUri'
  }
  return null
}

export { isValidDomain, normalizeDomain }
