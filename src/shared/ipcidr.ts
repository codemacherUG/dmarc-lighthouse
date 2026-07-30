import { isIPv4, isIPv6 } from 'net'

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
