export type DmarcPolicy = 'none' | 'quarantine' | 'reject'
export type AlignmentMode = 'r' | 's'
/** `same` = omit `sp=` (inherits organizational policy). */
export type SubdomainPolicyOption = 'same' | DmarcPolicy
export type FailureOption = '0' | '1' | 'd' | 's'

export type DmarcBuilderStep = 'domain' | 'policy' | 'reporting' | 'result'

export const BUILDER_STEPS: DmarcBuilderStep[] = ['domain', 'policy', 'reporting', 'result']

export interface DmarcBuilderInput {
  domain: string
  policy: DmarcPolicy
  subdomainPolicy: SubdomainPolicyOption
  /** 1–100; omitted from record when 100. */
  pct: number
  /** One or more report addresses (email or mailto:), comma/space separated. */
  rua: string
  ruf: string
  fo: FailureOption[]
  adkim: AlignmentMode
  aspf: AlignmentMode
}

export interface DmarcTag {
  key: string
  value: string
}

export interface DmarcRecordResult {
  domain: string
  host: string
  type: 'TXT'
  value: string
  tags: DmarcTag[]
}

export const DEFAULT_BUILDER_INPUT: DmarcBuilderInput = {
  domain: '',
  policy: 'none',
  subdomainPolicy: 'same',
  pct: 100,
  rua: '',
  ruf: '',
  fo: ['0'],
  adkim: 'r',
  aspf: 'r'
}

export function stepIndex(step: DmarcBuilderStep): number {
  return BUILDER_STEPS.indexOf(step)
}

export function normalizeDomain(raw: string): string {
  return raw.trim().toLowerCase().replace(/\.$/, '')
}

export function isValidDomain(raw: string): boolean {
  const domain = normalizeDomain(raw)
  return Boolean(domain) && /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(domain)
}

/** Suggested mailbox for rua=/ruf= (same address for both). */
export function defaultDmarcMailbox(domain: string): string {
  const d = normalizeDomain(domain)
  return d ? `dmarc@${d}` : ''
}

/** @deprecated use defaultDmarcMailbox */
export function defaultRuaMailbox(domain: string): string {
  return defaultDmarcMailbox(domain)
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

export function normalizeMailto(raw: string): string {
  const value = raw.trim()
  if (!value) return ''
  if (/^(mailto|https?):/i.test(value)) return value
  return `mailto:${value}`
}

export function normalizePolicy(value: unknown): DmarcPolicy {
  return value === 'quarantine' || value === 'reject' ? value : 'none'
}

export function normalizeAlignment(value: unknown): AlignmentMode {
  return value === 's' ? 's' : 'r'
}

export function normalizePct(value: unknown): number {
  const n = Math.round(Number(value))
  if (!Number.isFinite(n)) return 100
  return Math.min(100, Math.max(1, n))
}

export function normalizeFo(values: unknown): FailureOption[] {
  const allowed: FailureOption[] = ['0', '1', 'd', 's']
  const list = Array.isArray(values) ? values.map(String) : []
  const filtered = allowed.filter((v) => list.includes(v))
  return filtered.length > 0 ? filtered : ['0']
}

/** Build the TXT record and structured tags. */
export function buildDmarcRecord(input: DmarcBuilderInput): DmarcRecordResult {
  const domain = normalizeDomain(input.domain)
  const tags: DmarcTag[] = [
    { key: 'v', value: 'DMARC1' },
    { key: 'p', value: normalizePolicy(input.policy) }
  ]

  if (input.subdomainPolicy !== 'same') {
    tags.push({ key: 'sp', value: normalizePolicy(input.subdomainPolicy) })
  }

  const pct = normalizePct(input.pct)
  if (pct < 100) {
    tags.push({ key: 'pct', value: String(pct) })
  }

  const rua = splitAddresses(input.rua).map(normalizeMailto).filter(Boolean)
  if (rua.length > 0) {
    tags.push({ key: 'rua', value: rua.join(',') })
  }

  const ruf = splitAddresses(input.ruf).map(normalizeMailto).filter(Boolean)
  if (ruf.length > 0) {
    tags.push({ key: 'ruf', value: ruf.join(',') })
  }

  const fo = normalizeFo(input.fo)
  if (!(fo.length === 1 && fo[0] === '0')) {
    tags.push({ key: 'fo', value: fo.join(':') })
  }

  // Include alignment explicitly so the copied record is self-explanatory.
  tags.push({ key: 'adkim', value: normalizeAlignment(input.adkim) })
  tags.push({ key: 'aspf', value: normalizeAlignment(input.aspf) })

  const value = tags.map((t) => `${t.key}=${t.value}`).join('; ')
  return {
    domain,
    host: domain ? `_dmarc.${domain}` : '_dmarc',
    type: 'TXT',
    value,
    tags
  }
}

/** Prefill builder fields from an existing DMARC TXT record. */
export function parseDmarcRecord(record: string): Partial<DmarcBuilderInput> {
  const parts = record
    .split(';')
    .map((p) => p.trim())
    .filter(Boolean)
  const map = new Map<string, string>()
  for (const part of parts) {
    const eq = part.indexOf('=')
    if (eq <= 0) continue
    map.set(part.slice(0, eq).trim().toLowerCase(), part.slice(eq + 1).trim())
  }

  const out: Partial<DmarcBuilderInput> = {}
  if (map.has('p')) out.policy = normalizePolicy(map.get('p'))
  if (map.has('sp')) out.subdomainPolicy = normalizePolicy(map.get('sp'))
  else out.subdomainPolicy = 'same'
  if (map.has('pct')) out.pct = normalizePct(map.get('pct'))
  if (map.has('rua')) {
    out.rua = map
      .get('rua')!
      .split(',')
      .map((s) => s.trim().replace(/^mailto:/i, ''))
      .join(', ')
  }
  if (map.has('ruf')) {
    out.ruf = map
      .get('ruf')!
      .split(',')
      .map((s) => s.trim().replace(/^mailto:/i, ''))
      .join(', ')
  }
  if (map.has('fo')) {
    out.fo = normalizeFo(
      map
        .get('fo')!
        .split(/[:]/)
        .map((s) => s.trim())
    )
  }
  if (map.has('adkim')) out.adkim = normalizeAlignment(map.get('adkim'))
  if (map.has('aspf')) out.aspf = normalizeAlignment(map.get('aspf'))
  return out
}

export function validateBuilderStep(
  step: DmarcBuilderStep,
  input: DmarcBuilderInput
): string | null {
  if (step === 'domain' || step === 'result') {
    if (!isValidDomain(input.domain)) return 'builder.error.domain'
  }
  if (step === 'reporting' || step === 'result') {
    if (!splitAddresses(input.rua).length) return 'builder.error.rua'
  }
  const pct = normalizePct(input.pct)
  if (pct < 1 || pct > 100) return 'builder.error.pct'
  return null
}
