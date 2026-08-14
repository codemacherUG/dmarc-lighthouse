import { isValidDomain, normalizeDomain } from './dmarc-builder'
import { listToLines, linesToList } from './spf-builder'
import { parseMtaStsPolicy, parseMtaStsTxt } from './transport'

export type MtaStsMode = 'none' | 'testing' | 'enforce'
export type MtaStsBuilderStep = 'domain' | 'policy' | 'result'

export const MTA_STS_BUILDER_STEPS: MtaStsBuilderStep[] = ['domain', 'policy', 'result']

/** RFC 8461: max_age is 1–31557600 seconds (~1 year). */
export const MTA_STS_MAX_AGE_MIN = 1
export const MTA_STS_MAX_AGE_MAX = 31_557_600
/** RFC 8461 recommends at least two weeks; one week is the practical floor. */
export const MTA_STS_MAX_AGE_DEFAULT = 604_800

export interface MtaStsBuilderInput {
  domain: string
  mode: MtaStsMode
  /** MX patterns, one per line (`mail.example.com` or `*.example.net`). */
  mx: string[]
  maxAgeSeconds: number
  /**
   * Policy id for the TXT record. Empty = generate a timestamp id.
   * RFC 8461: 1–32 alphanumeric characters; must change when the policy changes.
   */
  id: string
}

export interface MtaStsDnsRecord {
  domain: string
  host: string
  type: 'TXT'
  value: string
}

export interface MtaStsRecordResult {
  domain: string
  dns: MtaStsDnsRecord
  policyText: string
  policyUrl: string
  httpsHost: string
  id: string
  mode: MtaStsMode
  mx: string[]
  maxAgeSeconds: number
}

export const DEFAULT_MTA_STS_BUILDER_INPUT: MtaStsBuilderInput = {
  domain: '',
  mode: 'testing',
  mx: [],
  maxAgeSeconds: MTA_STS_MAX_AGE_DEFAULT,
  id: ''
}

export function mtaStsStepIndex(step: MtaStsBuilderStep): number {
  return MTA_STS_BUILDER_STEPS.indexOf(step)
}

export function normalizeMtaStsMode(value: unknown): MtaStsMode {
  return value === 'enforce' || value === 'none' || value === 'testing' ? value : 'testing'
}

export function normalizeMaxAge(value: unknown): number {
  const n = Math.round(Number(value))
  if (!Number.isFinite(n)) return MTA_STS_MAX_AGE_DEFAULT
  return Math.min(MTA_STS_MAX_AGE_MAX, Math.max(MTA_STS_MAX_AGE_MIN, n))
}

/** RFC 8461 mx-host: DomainName or `*.` DomainName (exactly one label). */
export function isMtaStsMxPattern(value: string): boolean {
  const v = value.trim().toLowerCase().replace(/\.$/, '')
  if (!v) return false
  if (v.startsWith('*.')) return isValidDomain(v.slice(2))
  return isValidDomain(v)
}

export function normalizeMxPattern(raw: string): string {
  return raw.trim().toLowerCase().replace(/\.$/, '')
}

export function normalizeMtaStsBuilderInput(input: MtaStsBuilderInput): MtaStsBuilderInput {
  return {
    domain: normalizeDomain(input.domain),
    mode: normalizeMtaStsMode(input.mode),
    mx: [...new Set(input.mx.map(normalizeMxPattern).filter(isMtaStsMxPattern))],
    maxAgeSeconds: normalizeMaxAge(input.maxAgeSeconds),
    id: input.id.trim()
  }
}

/** UTC timestamp id, e.g. `20260814T091200` (15 alphanumeric chars). */
export function generateMtaStsId(date = new Date()): string {
  const pad = (n: number): string => String(n).padStart(2, '0')
  return `${date.getUTCFullYear()}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}T${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}`
}

export function isValidMtaStsId(value: string): boolean {
  return /^[A-Za-z0-9]{1,32}$/.test(value.trim())
}

export function buildMtaStsPolicyFile(input: MtaStsBuilderInput): string {
  const norm = normalizeMtaStsBuilderInput(input)
  const lines = ['version: STSv1', `mode: ${norm.mode}`]
  for (const host of norm.mx) {
    lines.push(`mx: ${host}`)
  }
  lines.push(`max_age: ${norm.maxAgeSeconds}`)
  return `${lines.join('\n')}\n`
}

export function buildMtaStsRecord(input: MtaStsBuilderInput, now = new Date()): MtaStsRecordResult {
  const norm = normalizeMtaStsBuilderInput(input)
  const id = isValidMtaStsId(norm.id) ? norm.id.trim() : generateMtaStsId(now)
  const host = norm.domain ? `_mta-sts.${norm.domain}` : '_mta-sts'
  return {
    domain: norm.domain,
    dns: {
      domain: norm.domain,
      host,
      type: 'TXT',
      value: `v=STSv1; id=${id}`
    },
    policyText: buildMtaStsPolicyFile({ ...norm, id }),
    policyUrl: norm.domain
      ? `https://mta-sts.${norm.domain}/.well-known/mta-sts.txt`
      : 'https://mta-sts./.well-known/mta-sts.txt',
    httpsHost: norm.domain ? `mta-sts.${norm.domain}` : 'mta-sts',
    id,
    mode: norm.mode,
    mx: norm.mx,
    maxAgeSeconds: norm.maxAgeSeconds
  }
}

export function parseMtaStsBuilderTxt(record: string): Partial<MtaStsBuilderInput> {
  const parsed = parseMtaStsTxt([record])
  if (!parsed.found) return {}
  return parsed.id ? { id: parsed.id } : {}
}

export function parseMtaStsBuilderPolicy(text: string): Partial<MtaStsBuilderInput> {
  const policy = parseMtaStsPolicy(text)
  const out: Partial<MtaStsBuilderInput> = {}
  if (policy.mode) out.mode = policy.mode
  if (policy.mx.length > 0) out.mx = policy.mx
  if (policy.maxAgeSeconds != null) out.maxAgeSeconds = normalizeMaxAge(policy.maxAgeSeconds)
  return out
}

function fingerprint(mode: MtaStsMode, mx: string[], maxAge: number): string {
  return JSON.stringify({ mode, mx: [...mx].sort(), maxAge })
}

/** True when mode, MX set and max_age match (id is ignored). */
export function mtaStsPoliciesEquivalent(
  a: Partial<Pick<MtaStsBuilderInput, 'mode' | 'mx' | 'maxAgeSeconds'>>,
  b: Partial<Pick<MtaStsBuilderInput, 'mode' | 'mx' | 'maxAgeSeconds'>>
): boolean {
  const left = normalizeMtaStsBuilderInput({ ...DEFAULT_MTA_STS_BUILDER_INPUT, ...a })
  const right = normalizeMtaStsBuilderInput({ ...DEFAULT_MTA_STS_BUILDER_INPUT, ...b })
  return (
    fingerprint(left.mode, left.mx, left.maxAgeSeconds) ===
    fingerprint(right.mode, right.mx, right.maxAgeSeconds)
  )
}

export function validateMtaStsBuilderStep(
  step: MtaStsBuilderStep,
  input: MtaStsBuilderInput
): string | null {
  const norm = normalizeMtaStsBuilderInput(input)
  if (step === 'domain' || step === 'result') {
    if (!isValidDomain(norm.domain)) return 'mtaStsBuilder.error.domain'
  }
  if (step === 'policy' || step === 'result') {
    const rawMx = input.mx.map(normalizeMxPattern).filter(Boolean)
    if (rawMx.length === 0) return 'mtaStsBuilder.error.mx'
    for (const raw of rawMx) {
      if (!isMtaStsMxPattern(raw)) return 'mtaStsBuilder.error.mxPattern'
    }
    const age = Number(input.maxAgeSeconds)
    if (!Number.isFinite(age) || age < MTA_STS_MAX_AGE_MIN || age > MTA_STS_MAX_AGE_MAX) {
      return 'mtaStsBuilder.error.maxAge'
    }
  }
  return null
}

export { isValidDomain, listToLines, linesToList, normalizeDomain }
