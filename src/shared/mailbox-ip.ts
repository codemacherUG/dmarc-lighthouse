/**
 * Offline mailbox-provider IP heuristics for DMARC noise filtering
 * (no Node `net` / enrichment). Covers Gmail, Outlook/Microsoft 365,
 * Yahoo/AOL and iCloud blocks commonly seen as forwarding / report-echo.
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

function toV4Ranges(cidrs: string[]): Array<{ start: number; end: number }> {
  return cidrs.map(ipv4CidrToRange).filter((r): r is { start: number; end: number } => r != null)
}

/** Well-known Google public IPv4 blocks (goog.json / mail egress). */
const GOOGLE_V4_RANGES = toV4Ranges([
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
])

/**
 * Exchange Online / Outlook.com egress (Microsoft 365 URL & IP list).
 * Intentionally not all of Azure — customer VMs stay visible.
 */
const MICROSOFT_V4_RANGES = toV4Ranges([
  '13.107.128.0/22',
  '23.103.160.0/20',
  '40.92.0.0/15',
  '40.96.0.0/13',
  '40.104.0.0/15',
  '40.107.0.0/16',
  '52.96.0.0/14',
  '52.100.0.0/14',
  '104.47.0.0/17',
  '132.245.0.0/16',
  '150.171.32.0/22'
])

/** Yahoo Mail / AOL outbound blocks seen in aggregate reports. */
const YAHOO_V4_RANGES = toV4Ranges([
  '66.163.160.0/19',
  '67.195.0.0/16',
  '68.142.192.0/18',
  '68.180.128.0/17',
  '69.147.64.0/18',
  '74.6.0.0/16',
  '98.136.0.0/14',
  '202.160.128.0/20',
  '209.191.64.0/18'
])

/** iCloud Mail ranges inside Apple's 17.0.0.0/8 (not the whole Apple net). */
const APPLE_V4_RANGES = toV4Ranges(['17.42.0.0/16', '17.57.0.0/16', '17.58.0.0/16'])

const MAILBOX_V4_RANGES = [
  ...GOOGLE_V4_RANGES,
  ...MICROSOFT_V4_RANGES,
  ...YAHOO_V4_RANGES,
  ...APPLE_V4_RANGES
]

/**
 * Well-known mailbox IPv6 prefixes as lowercase string starts.
 * Handles compressed forms like 2a00:1450:4864:20::346.
 */
const MAILBOX_V6_PREFIXES = [
  // Google
  '2001:4860:',
  '2404:6800:',
  '2404:f340:',
  '2600:1900:',
  '2607:f8b0:',
  '2620:120:',
  '2800:3f0:',
  '2a00:1450:',
  '2c0f:fb50:',
  // Microsoft 365 / Outlook
  '2a01:111:f400:',
  '2a01:111:f403:',
  '2603:1006:',
  '2603:1016:',
  '2603:1026:',
  '2603:1036:',
  '2603:1046:',
  '2603:1056:',
  '2603:1096:',
  '2603:1097:',
  '2603:1098:',
  '2603:1099:',
  '2603:10b6:',
  '2603:10d6:',
  '2620:1ec:',
  // Yahoo
  '2001:4998:',
  '2406:8600:',
  // Apple iCloud
  '2620:149:',
  '2a01:b740:'
]

function isLikelyMailboxIpv6(ip: string): boolean {
  const lower = ip.toLowerCase()
  for (const prefix of MAILBOX_V6_PREFIXES) {
    if (lower.startsWith(prefix)) return true
  }
  for (const prefix of MAILBOX_V6_PREFIXES) {
    const bare = prefix.slice(0, -1)
    if (lower === bare || lower.startsWith(`${bare}::`)) return true
  }
  return false
}

/** True when the IP is in a well-known mailbox-provider address block. */
export function isLikelyMailboxIp(ip: string): boolean {
  const trimmed = ip.trim()
  if (!trimmed) return false
  if (trimmed.includes(':')) return isLikelyMailboxIpv6(trimmed)
  const n = ipv4ToInt(trimmed)
  if (n == null) return false
  return MAILBOX_V4_RANGES.some((r) => n >= r.start && n <= r.end)
}
