import { isValidDomain, normalizeDomain } from './dmarc-builder'

export type BimiBuilderStep = 'domain' | 'logo' | 'result'

export const BIMI_BUILDER_STEPS: BimiBuilderStep[] = ['domain', 'logo', 'result']

export const DEFAULT_BIMI_SELECTOR = 'default'

export interface BimiBuilderInput {
  domain: string
  /** DNS selector; record lives at `{selector}._bimi.{domain}`. */
  selector: string
  /** HTTPS URL of the SVG Tiny PS logo (`l=`). */
  location: string
  /** Optional HTTPS URL of the VMC/CMC PEM (`a=`). */
  authority: string
}

export interface BimiTag {
  key: string
  value: string
}

export interface BimiRecordResult {
  domain: string
  selector: string
  host: string
  type: 'TXT'
  value: string
  tags: BimiTag[]
}

export interface ParsedBimiRecord {
  found: boolean
  location: string | null
  authority: string | null
}

export type BimiDmarcPrereq = 'ok' | 'missing' | 'policy' | 'pct'

export const DEFAULT_BIMI_BUILDER_INPUT: BimiBuilderInput = {
  domain: '',
  selector: DEFAULT_BIMI_SELECTOR,
  location: '',
  authority: ''
}

export function bimiStepIndex(step: BimiBuilderStep): number {
  return BIMI_BUILDER_STEPS.indexOf(step)
}

/** Strip `._bimi` / a full hostname; empty becomes `default`. */
export function normalizeBimiSelector(raw: string): string {
  let s = raw.trim().toLowerCase().replace(/\.+$/, '')
  const marker = '._bimi'
  const idx = s.indexOf(marker)
  if (idx >= 0) s = s.slice(0, idx)
  return s || DEFAULT_BIMI_SELECTOR
}

/** BIMI selector is a DNS label (1–63, LDH). */
export function isValidBimiSelector(raw: string): boolean {
  const s = normalizeBimiSelector(raw)
  return s.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(s)
}

/** HTTPS URI as published in `l=` / `a=`. Empty input → null. */
export function normalizeBimiHttpsUrl(raw: string): string | null {
  const value = raw.trim()
  if (!value) return null
  if (!/^https:\/\//i.test(value)) return null
  try {
    const url = new URL(value)
    if (url.protocol !== 'https:') return null
    if (!url.hostname) return null
    return value
  } catch {
    return null
  }
}

export function bimiHost(domain: string, selector = DEFAULT_BIMI_SELECTOR): string {
  const d = normalizeDomain(domain)
  const s = normalizeBimiSelector(selector)
  return d ? `${s}._bimi.${d}` : `${s}._bimi`
}

function parseTags(record: string): Map<string, string> {
  const map = new Map<string, string>()
  for (const part of record.split(';')) {
    const token = part.trim()
    if (!token) continue
    const eq = token.indexOf('=')
    if (eq <= 0) continue
    const key = token.slice(0, eq).trim().toLowerCase()
    const value = token
      .slice(eq + 1)
      .trim()
      .replace(/^["']|["']$/g, '')
    map.set(key, value)
  }
  return map
}

export function parseBimiRecord(record: string): ParsedBimiRecord {
  const map = parseTags(record)
  if ((map.get('v') ?? '').toUpperCase() !== 'BIMI1') {
    return { found: false, location: null, authority: null }
  }
  return {
    found: true,
    location: map.has('l') ? map.get('l')! : null,
    authority: map.has('a') ? map.get('a')! : null
  }
}

export function buildBimiRecord(input: BimiBuilderInput): BimiRecordResult {
  const domain = normalizeDomain(input.domain)
  const selector = normalizeBimiSelector(input.selector)
  const location = normalizeBimiHttpsUrl(input.location) ?? input.location.trim()
  const authority = normalizeBimiHttpsUrl(input.authority) ?? input.authority.trim()
  const tags: BimiTag[] = [
    { key: 'v', value: 'BIMI1' },
    { key: 'l', value: location }
  ]
  if (authority) tags.push({ key: 'a', value: authority })
  return {
    domain,
    selector,
    host: bimiHost(domain, selector),
    type: 'TXT',
    value: tags.map((t) => `${t.key}=${t.value}`).join('; '),
    tags
  }
}

/** Prefill builder fields from an existing BIMI TXT record. */
export function parseBimiBuilderRecord(record: string): Partial<BimiBuilderInput> {
  const parsed = parseBimiRecord(record)
  if (!parsed.found) return {}
  const out: Partial<BimiBuilderInput> = {}
  if (parsed.location != null) out.location = parsed.location
  if (parsed.authority != null) out.authority = parsed.authority
  return out
}

export function bimiRecordsEquivalent(a: string, b: string): boolean {
  const left = parseBimiRecord(a)
  const right = parseBimiRecord(b)
  if (!left.found || !right.found) {
    return a.replace(/\s+/g, '') === b.replace(/\s+/g, '')
  }
  return (
    (left.location ?? '') === (right.location ?? '') &&
    (left.authority ?? '') === (right.authority ?? '')
  )
}

function dmarcPct(records: string[]): number | null {
  const joined = records.find((r) => /v\s*=\s*DMARC1/i.test(r)) ?? records[0] ?? ''
  const match = /(?:^|;)\s*pct\s*=\s*(\d+)/i.exec(joined)
  if (!match) return null
  const n = Number(match[1])
  return Number.isFinite(n) ? n : null
}

/** BIMI receivers require DMARC p=quarantine or reject at 100 %. */
export function bimiDmarcPrereq(
  policy: string | null | undefined,
  records: string[] = []
): { ok: boolean; reason: BimiDmarcPrereq; policy: string | null; pct: number | null } {
  const pct = dmarcPct(records)
  const p = (policy ?? '').trim().toLowerCase()
  if (!p) return { ok: false, reason: 'missing', policy: null, pct }
  if (p !== 'quarantine' && p !== 'reject') {
    return { ok: false, reason: 'policy', policy: p, pct }
  }
  if (pct != null && pct < 100) return { ok: false, reason: 'pct', policy: p, pct }
  return { ok: true, reason: 'ok', policy: p, pct }
}

export function validateBimiBuilderStep(
  step: BimiBuilderStep,
  input: BimiBuilderInput
): string | null {
  if (step === 'domain' || step === 'result') {
    if (!isValidDomain(input.domain)) return 'bimiBuilder.error.domain'
  }
  if (step === 'logo' || step === 'result') {
    if (!isValidBimiSelector(input.selector)) return 'bimiBuilder.error.selector'
    if (!normalizeBimiHttpsUrl(input.location)) return 'bimiBuilder.error.location'
    if (input.authority.trim() && !normalizeBimiHttpsUrl(input.authority)) {
      return 'bimiBuilder.error.authority'
    }
  }
  return null
}

export { isValidDomain, normalizeDomain }
