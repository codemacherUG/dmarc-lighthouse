import { isValidDomain, normalizeDomain } from './dmarc-builder'

export type SpfAllQualifier = '-all' | '~all' | '?all' | '+all'
export type SpfBuilderStep = 'domain' | 'mechanisms' | 'result'

export const SPF_BUILDER_STEPS: SpfBuilderStep[] = ['domain', 'mechanisms', 'result']

export interface SpfBuilderInput {
  domain: string
  /** include: hostnames (without include: prefix). */
  includes: string[]
  /** ip4: values (IP or CIDR). */
  ip4: string[]
  /** ip6: values (IP or CIDR). */
  ip6: string[]
  useA: boolean
  useMx: boolean
  all: SpfAllQualifier
}

export interface SpfTerm {
  key: string
  value: string
}

export interface SpfRecordResult {
  domain: string
  host: string
  type: 'TXT'
  value: string
  terms: SpfTerm[]
}

export const DEFAULT_SPF_BUILDER_INPUT: SpfBuilderInput = {
  domain: '',
  includes: [],
  ip4: [],
  ip6: [],
  useA: false,
  useMx: false,
  all: '-all'
}

export function spfStepIndex(step: SpfBuilderStep): number {
  return SPF_BUILDER_STEPS.indexOf(step)
}

function splitLines(raw: string): string[] {
  return [
    ...new Set(
      raw
        .split(/[\n,;]+/)
        .map((s) => s.trim())
        .filter(Boolean)
    )
  ]
}

/** Hostnames allowed in include:/a:/mx: (may contain underscores). */
export function isSpfDnsName(value: string): boolean {
  const v = value.trim().toLowerCase().replace(/\.$/, '')
  return Boolean(v) && /^[a-z0-9_]([a-z0-9._-]*[a-z0-9_])?$/i.test(v)
}

export function normalizeSpfAll(value: unknown): SpfAllQualifier {
  if (value === '~all' || value === '?all' || value === '+all' || value === '-all') return value
  return '-all'
}

function stripIpPrefix(raw: string, kind: 'ip4' | 'ip6'): string {
  const s = raw.trim()
  const re = kind === 'ip4' ? /^ip4:/i : /^ip6:/i
  return s.replace(re, '').trim()
}

function stripInclude(raw: string): string {
  return raw.trim().replace(/^include:/i, '').toLowerCase().replace(/\.$/, '')
}

export function normalizeSpfBuilderInput(input: SpfBuilderInput): SpfBuilderInput {
  return {
    domain: normalizeDomain(input.domain),
    includes: input.includes.map(stripInclude).filter(isSpfDnsName),
    ip4: input.ip4.map((v) => stripIpPrefix(v, 'ip4')).filter(Boolean),
    ip6: input.ip6.map((v) => stripIpPrefix(v, 'ip6')).filter(Boolean),
    useA: Boolean(input.useA),
    useMx: Boolean(input.useMx),
    all: normalizeSpfAll(input.all)
  }
}

/** Build a v=spf1 TXT record from structured fields. */
export function buildSpfRecord(input: SpfBuilderInput): SpfRecordResult {
  const norm = normalizeSpfBuilderInput(input)
  const terms: SpfTerm[] = [{ key: 'v', value: 'spf1' }]

  for (const inc of norm.includes) {
    terms.push({ key: 'include', value: inc })
  }
  for (const ip of norm.ip4) {
    terms.push({ key: 'ip4', value: ip })
  }
  for (const ip of norm.ip6) {
    terms.push({ key: 'ip6', value: ip })
  }
  if (norm.useA) terms.push({ key: 'a', value: '' })
  if (norm.useMx) terms.push({ key: 'mx', value: '' })
  terms.push({ key: 'all', value: norm.all })

  const parts = ['v=spf1']
  for (const term of terms) {
    if (term.key === 'v') continue
    if (term.key === 'all') {
      parts.push(term.value)
      continue
    }
    if (term.key === 'a' || term.key === 'mx') {
      parts.push(term.key)
      continue
    }
    parts.push(`${term.key}:${term.value}`)
  }

  return {
    domain: norm.domain,
    host: '@',
    type: 'TXT',
    value: parts.join(' '),
    terms
  }
}

/** Prefill builder fields from an existing SPF TXT record. */
export function parseSpfRecord(record: string): Partial<SpfBuilderInput> {
  const tokens = record
    .trim()
    .split(/\s+/)
    .map((t) => t.trim())
    .filter(Boolean)

  const includes: string[] = []
  const ip4: string[] = []
  const ip6: string[] = []
  let useA = false
  let useMx = false
  let all: SpfAllQualifier = '-all'

  for (const raw of tokens) {
    if (/^v\s*=\s*spf1$/i.test(raw)) continue
    const term = /^[+\-~?]/.test(raw) && !/^[+\-~?]?all$/i.test(raw) ? raw.slice(1) : raw
    const lower = term.toLowerCase()

    if (lower === '-all' || lower === '~all' || lower === '?all' || lower === '+all') {
      all = lower
      continue
    }
    if (lower === 'all') {
      all = '+all'
      continue
    }
    if (lower.startsWith('include:')) {
      const host = stripInclude(term)
      if (host) includes.push(host)
      continue
    }
    if (lower.startsWith('ip4:')) {
      const v = stripIpPrefix(term, 'ip4')
      if (v) ip4.push(v)
      continue
    }
    if (lower.startsWith('ip6:')) {
      const v = stripIpPrefix(term, 'ip6')
      if (v) ip6.push(v)
      continue
    }
    if (lower === 'a' || lower.startsWith('a:') || lower.startsWith('a/')) {
      useA = true
      continue
    }
    if (lower === 'mx' || lower.startsWith('mx:') || lower.startsWith('mx/')) {
      useMx = true
    }
  }

  return { includes, ip4, ip6, useA, useMx, all }
}

export function linesToList(raw: string): string[] {
  return splitLines(raw)
}

export function listToLines(list: readonly string[]): string {
  return list.join('\n')
}

/**
 * Order-independent mechanism fingerprint.
 * Strips default `+` qualifiers so `+a` ≡ `a`, ignores mechanism order.
 */
export function normalizeSpfMechanisms(record: string): string[] {
  const out: string[] = []
  for (const raw of record
    .trim()
    .split(/\s+/)
    .map((t) => t.trim())
    .filter(Boolean)) {
    if (/^v\s*=\s*spf1$/i.test(raw)) continue

    if (/^[+\-~?]?all$/i.test(raw)) {
      const lower = raw.toLowerCase()
      out.push(lower === 'all' || lower === '+all' ? '+all' : lower)
      continue
    }

    let term = raw
    const qualifier = term[0]
    if (qualifier === '+' || qualifier === '-' || qualifier === '~' || qualifier === '?') {
      if (qualifier === '+') {
        term = term.slice(1)
      } else {
        // Non-default qualifier changes meaning — keep it.
        out.push(term.toLowerCase())
        continue
      }
    }

    const lower = term.toLowerCase()
    if (lower.startsWith('include:')) {
      out.push(`include:${stripInclude(term)}`)
      continue
    }
    if (lower.startsWith('ip4:')) {
      out.push(`ip4:${stripIpPrefix(term, 'ip4').toLowerCase()}`)
      continue
    }
    if (lower.startsWith('ip6:')) {
      out.push(`ip6:${stripIpPrefix(term, 'ip6').toLowerCase()}`)
      continue
    }
    if (lower === 'a' || lower.startsWith('a:') || lower.startsWith('a/')) {
      out.push(lower === 'a' ? 'a' : lower)
      continue
    }
    if (lower === 'mx' || lower.startsWith('mx:') || lower.startsWith('mx/')) {
      out.push(lower === 'mx' ? 'mx' : lower)
      continue
    }
    out.push(lower)
  }
  return out.sort()
}

/** True when two SPF records are equivalent aside from whitespace, `+`, and mechanism order. */
export function spfRecordsEquivalent(a: string, b: string): boolean {
  const left = normalizeSpfMechanisms(a)
  const right = normalizeSpfMechanisms(b)
  if (left.length !== right.length) return false
  return left.every((value, index) => value === right[index])
}

export function validateSpfBuilderStep(
  step: SpfBuilderStep,
  input: SpfBuilderInput
): string | null {
  const norm = normalizeSpfBuilderInput(input)
  if (step === 'domain' || step === 'result') {
    if (!isValidDomain(norm.domain)) return 'spfBuilder.error.domain'
  }
  if (step === 'mechanisms' || step === 'result') {
    const hasMechanism =
      norm.includes.length > 0 ||
      norm.ip4.length > 0 ||
      norm.ip6.length > 0 ||
      norm.useA ||
      norm.useMx
    if (!hasMechanism) return 'spfBuilder.error.mechanisms'
    for (const inc of input.includes.map(stripInclude).filter(Boolean)) {
      if (!isSpfDnsName(inc)) return 'spfBuilder.error.include'
    }
  }
  return null
}

export { isValidDomain, normalizeDomain }
