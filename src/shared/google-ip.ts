/**
 * Offline Google IP heuristics for DMARC noise filtering (no Node `net` / enrichment).
 * Covers the common Google mail / infrastructure blocks seen in aggregate reports.
 */

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  let n = 0
  for (const p of parts) {
    const octet = Number(p)
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) return null
    n = (n << 8) + octet
  }
  return n >>> 0
}

function ipv4CidrToRange(cidr: string): { start: number; end: number } | null {
  const [addr, lenStr] = cidr.split('/')
  if (!addr || !lenStr) return null
  const len = Number(lenStr)
  if (!Number.isInteger(len) || len < 0 || len > 32) return null
  const ipInt = ipv4ToInt(addr)
  if (ipInt == null) return null
  const mask = len === 0 ? 0 : (~0 << (32 - len)) >>> 0
  const start = (ipInt & mask) >>> 0
  const end = (start + (2 ** (32 - len) - 1)) >>> 0
  return { start, end }
}

/** Well-known Google public IPv4 blocks (goog.json / mail egress). */
const GOOGLE_V4_RANGES: Array<{ start: number; end: number }> = [
  '8.34.208.0/20',
  '8.35.192.0/20',
  '64.233.160.0/19',
  '66.102.0.0/20',
  '66.249.64.0/19',
  '72.14.192.0/18',
  '74.125.0.0/16',
  '108.177.0.0/17',
  '142.250.0.0/15',
  '172.217.0.0/16',
  '173.194.0.0/16',
  '209.85.128.0/17',
  '216.58.192.0/19',
  '216.239.32.0/19'
]
  .map(ipv4CidrToRange)
  .filter((r): r is { start: number; end: number } => r != null)

/**
 * Well-known Google IPv6 /32 (and similar) prefixes as lowercase string starts.
 * Handles compressed forms like 2a00:1450:4864:20::346.
 */
const GOOGLE_V6_PREFIXES = [
  '2001:4860:',
  '2404:6800:',
  '2404:f340:',
  '2600:1900:',
  '2607:f8b0:',
  '2620:120:',
  '2800:3f0:',
  '2a00:1450:',
  '2c0f:fb50:'
]

function isLikelyGoogleIpv6(ip: string): boolean {
  const lower = ip.toLowerCase()
  // Expand a leading compressed form "::xxxx" is rare for Google; common is prefix:…
  for (const prefix of GOOGLE_V6_PREFIXES) {
    if (lower.startsWith(prefix)) return true
  }
  // Compressed at the prefix boundary, e.g. 2a00:1450::1
  for (const prefix of GOOGLE_V6_PREFIXES) {
    const bare = prefix.slice(0, -1) // drop trailing ':'
    if (lower === bare || lower.startsWith(`${bare}::`)) return true
  }
  return false
}

/** True when the IP is in a well-known Google address block. */
export function isLikelyGoogleIp(ip: string): boolean {
  const trimmed = ip.trim()
  if (!trimmed) return false
  if (trimmed.includes(':')) return isLikelyGoogleIpv6(trimmed)
  const n = ipv4ToInt(trimmed)
  if (n == null) return false
  return GOOGLE_V4_RANGES.some((r) => n >= r.start && n <= r.end)
}
