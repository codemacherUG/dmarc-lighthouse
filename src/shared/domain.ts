/**
 * Multi-label public suffixes that need three labels for the organizational domain.
 * A full Public Suffix List would be more exact; this covers the suffixes that
 * actually show up in DMARC reports without shipping a 200 kB table.
 */
const MULTI_LABEL_SUFFIXES = new Set([
  'co.uk',
  'org.uk',
  'ac.uk',
  'gov.uk',
  'me.uk',
  'net.uk',
  'sch.uk',
  'com.au',
  'net.au',
  'org.au',
  'edu.au',
  'gov.au',
  'co.nz',
  'net.nz',
  'org.nz',
  'co.za',
  'org.za',
  'co.jp',
  'or.jp',
  'ne.jp',
  'ac.jp',
  'go.jp',
  'com.br',
  'net.br',
  'org.br',
  'com.mx',
  'com.ar',
  'com.tr',
  'com.cn',
  'com.hk',
  'com.sg',
  'com.tw',
  'co.in',
  'net.in',
  'org.in',
  'co.il',
  'co.kr',
  'com.pl',
  'com.ua',
  'com.es'
])

/** Lowercased host without a trailing dot, or null when unusable. */
export function normalizeHost(host: string | null | undefined): string | null {
  const trimmed = (host ?? '').trim().toLowerCase().replace(/\.$/, '')
  if (!trimmed || !trimmed.includes('.')) return trimmed || null
  return trimmed
}

/**
 * Registrable ("organizational") domain used for DMARC relaxed alignment,
 * e.g. `mail.eu.example.co.uk` → `example.co.uk`.
 */
export function organizationalDomain(host: string | null | undefined): string | null {
  const normalized = normalizeHost(host)
  if (!normalized) return null
  // An address instead of a host: use the part after the last @.
  const bare = normalized.includes('@')
    ? normalized.slice(normalized.lastIndexOf('@') + 1)
    : normalized
  const labels = bare.split('.').filter(Boolean)
  if (labels.length <= 2) return labels.join('.') || null
  const lastTwo = labels.slice(-2).join('.')
  const take = MULTI_LABEL_SUFFIXES.has(lastTwo) ? 3 : 2
  return labels.slice(-take).join('.')
}

/** DMARC relaxed alignment: both hosts share an organizational domain. */
export function isRelaxedAligned(
  authDomain: string | null | undefined,
  fromDomain: string | null | undefined
): boolean {
  const a = organizationalDomain(authDomain)
  const b = organizationalDomain(fromDomain)
  return Boolean(a && b && a === b)
}
