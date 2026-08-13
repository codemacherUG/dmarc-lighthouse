/** Lightweight checks so this shared module stays free of Node built-ins (web tsconfig). */
function isIPv4(addr: string): boolean {
  const parts = addr.split('.')
  if (parts.length !== 4) return false
  return parts.every((p) => {
    if (!/^\d{1,3}$/.test(p)) return false
    const n = Number(p)
    return n >= 0 && n <= 255 && String(n) === p
  })
}

function isIPv6(addr: string): boolean {
  // Enough for CIDR matching; rejects obvious non-IPv6 strings.
  if (!addr || addr.includes('.')) return false
  return /^[0-9a-fA-F:]+$/.test(addr) && addr.includes(':')
}

export interface CloudPrefix {
  provider: string
  /** IPv4 network as integer start/end, or IPv6 CIDR string. */
  kind: 'v4' | 'v6'
  start?: number
  end?: number
  cidr?: string
  prefixLen?: number
}

function ipv4ToInt(ip: string): number {
  const parts = ip.split('.').map((p) => Number(p))
  return ((parts[0]! << 24) >>> 0) + (parts[1]! << 16) + (parts[2]! << 8) + parts[3]!
}

/** Parse CIDR into a CloudPrefix entry. */
export function parseCidr(provider: string, cidr: string): CloudPrefix | null {
  const [addr, lenStr] = cidr.split('/')
  if (!addr || !lenStr) return null
  const len = Number(lenStr)
  if (!Number.isFinite(len)) return null
  if (isIPv4(addr)) {
    if (len < 0 || len > 32) return null
    const ipInt = ipv4ToInt(addr)
    const mask = len === 0 ? 0 : (~0 << (32 - len)) >>> 0
    const start = (ipInt & mask) >>> 0
    const end = (start + (2 ** (32 - len) - 1)) >>> 0
    return { provider, kind: 'v4', start, end, cidr, prefixLen: len }
  }
  if (isIPv6(addr)) {
    if (len < 0 || len > 128) return null
    return { provider, kind: 'v6', cidr, prefixLen: len }
  }
  return null
}

function ipv6Matches(ip: string, cidr: string, prefixLen: number): boolean {
  const [network] = cidr.split('/')
  if (!network) return false
  const ipBits = ipv6ToBits(ip)
  const netBits = ipv6ToBits(network)
  if (!ipBits || !netBits) return false
  for (let i = 0; i < prefixLen; i++) {
    if (ipBits[i] !== netBits[i]) return false
  }
  return true
}

function ipv6ToBits(ip: string): number[] | null {
  const parts = ip.toLowerCase().split('::')
  let head: string[] = []
  let tail: string[] = []
  if (parts.length === 1) {
    head = ip.toLowerCase().split(':')
  } else if (parts.length === 2) {
    head = parts[0] ? parts[0].split(':') : []
    tail = parts[1] ? parts[1].split(':') : []
  } else {
    return null
  }
  head = head.filter(Boolean)
  tail = tail.filter(Boolean)
  const missing = 8 - head.length - tail.length
  if (missing < 0) return null
  const full = [...head, ...Array(missing).fill('0'), ...tail]
  if (full.length !== 8) return null
  const bits: number[] = []
  for (const g of full) {
    const n = parseInt(g, 16)
    if (!Number.isFinite(n)) return null
    for (let i = 15; i >= 0; i--) bits.push((n >> i) & 1)
  }
  return bits
}

/**
 * Fixed-width sort key for an IP: lexicographic order equals numeric order and
 * IPv4 sorts before IPv6. Returns null for values that are not an IP address.
 */
export function ipSortKey(ip: string): string | null {
  const s = ip.trim()
  if (isIPv4(s)) return `4${ipv4ToInt(s).toString(16).padStart(8, '0')}`
  if (!isIPv6(s)) return null
  const bits = ipv6ToBits(s)
  if (!bits) return null
  let out = '6'
  for (let i = 0; i < 128; i += 4) {
    out += ((bits[i]! << 3) | (bits[i + 1]! << 2) | (bits[i + 2]! << 1) | bits[i + 3]!).toString(16)
  }
  return out
}

/**
 * Normalize one authorized-sender entry (bare IP or CIDR).
 * Returns canonical CIDR string, or null if invalid.
 */
export function normalizeAuthorizedSenderEntry(raw: string): string | null {
  const s = raw.trim()
  if (!s || s.startsWith('#')) return null
  if (s.includes('/')) {
    return parseCidr('authorized', s) ? s : null
  }
  if (isIPv4(s)) {
    const cidr = `${s}/32`
    return parseCidr('authorized', cidr) ? cidr : null
  }
  if (isIPv6(s)) {
    const cidr = `${s}/128`
    return parseCidr('authorized', cidr) ? cidr : null
  }
  return null
}

/** Parse authorized sender list (IPs/CIDRs) into matchable prefixes. */
export function parseAuthorizedSenderPrefixes(entries: readonly string[]): CloudPrefix[] {
  const out: CloudPrefix[] = []
  const seen = new Set<string>()
  for (const raw of entries) {
    const cidr = normalizeAuthorizedSenderEntry(raw)
    if (!cidr || seen.has(cidr)) continue
    seen.add(cidr)
    const prefix = parseCidr('authorized', cidr)
    if (prefix) out.push(prefix)
  }
  return out
}

/** True when `ip` matches any authorized sender prefix. */
export function isAuthorizedSender(ip: string, prefixes: CloudPrefix[]): boolean {
  if (!prefixes.length) return false
  return matchCloudProvider(ip, prefixes) != null
}

/** Longest-prefix match against loaded ranges. */
export function matchCloudProvider(ip: string, prefixes: CloudPrefix[]): string | null {
  const trimmed = ip.trim()
  let best: CloudPrefix | null = null

  if (isIPv4(trimmed)) {
    const n = ipv4ToInt(trimmed)
    for (const p of prefixes) {
      if (p.kind !== 'v4' || p.start == null || p.end == null) continue
      if (n >= p.start && n <= p.end) {
        if (!best || (p.prefixLen ?? 0) > (best.prefixLen ?? 0)) best = p
      }
    }
    return best?.provider ?? null
  }

  if (isIPv6(trimmed)) {
    for (const p of prefixes) {
      if (p.kind !== 'v6' || !p.cidr || p.prefixLen == null) continue
      if (ipv6Matches(trimmed, p.cidr, p.prefixLen)) {
        if (!best || p.prefixLen > (best.prefixLen ?? 0)) best = p
      }
    }
    return best?.provider ?? null
  }

  return null
}
