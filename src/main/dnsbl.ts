import { isIP } from 'net'
import { configureDnsEnvironment, resolve4Reliable } from './dns-env'

const LOOKUP_TIMEOUT_MS = 2000

/** Lists queried for reputation signals. */
const BLOCKLISTS = [{ name: 'spamhaus-zen', zone: 'zen.spamhaus.org' }] as const
const WHITELISTS = [{ name: 'dnswl', zone: 'list.dnswl.org' }] as const

/** Reverse an IP for DNSBL queries (IPv4 dotted-quad or IPv6 nibble form). */
export function reverseIpForDnsbl(ip: string): string | null {
  const kind = isIP(ip)
  if (kind === 4) {
    return ip.split('.').reverse().join('.')
  }
  if (kind === 6) {
    const expanded = expandIpv6(ip)
    if (!expanded) return null
    return expanded.replace(/:/g, '').split('').reverse().join('.')
  }
  return null
}

function expandIpv6(ip: string): string | null {
  const parts = ip.toLowerCase().split('::')
  if (parts.length > 2) return null
  let head = parts[0] ? parts[0].split(':') : []
  let tail = parts[1] ? parts[1].split(':') : []
  if (parts.length === 1) {
    head = ip.toLowerCase().split(':')
    tail = []
  }
  head = head.filter(Boolean)
  tail = tail.filter(Boolean)
  const missing = 8 - head.length - tail.length
  if (missing < 0) return null
  const full = [...head, ...Array(missing).fill('0'), ...tail]
  if (full.length !== 8) return null
  return full.map((g) => g.padStart(4, '0')).join(':')
}

async function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => reject(new Error('timeout')), ms)
      })
    ])
  } finally {
    if (timer) clearTimeout(timer)
  }
}

/**
 * True only for real list hits.
 * Spamhaus error codes (127.255.255.0/24) — e.g. public/open resolver — must NOT count.
 * Valid ZEN listings are 127.0.0.2–127.0.0.11; DNSWL uses 127.0.x.y categories.
 */
export function isListedDnsblAnswer(answers: string[]): boolean {
  if (!answers.length) return false
  for (const raw of answers) {
    const parts = raw.split('.').map((p) => Number(p))
    if (parts.length !== 4 || parts.some((n) => !Number.isFinite(n))) continue
    const [a, b, c] = parts as [number, number, number, number]
    // Anything outside 127.0.0.0/8 is resolver noise / hijacking.
    if (a !== 127) continue
    // Spamhaus (and common) error / policy range — not a listing.
    if (b === 255 && c === 255) continue
    // Real DNSxL answers live in 127.0.0.0/16 (IP lists) or nearby 127.0.x.
    if (b === 0) return true
  }
  return false
}

async function queryZone(reversed: string, zone: string): Promise<boolean> {
  try {
    const answers = await withTimeout(resolve4Reliable(`${reversed}.${zone}`), LOOKUP_TIMEOUT_MS)
    return isListedDnsblAnswer(Array.isArray(answers) ? answers : [])
  } catch {
    // NXDOMAIN / timeout / SERVFAIL → not listed
    return false
  }
}

/** Return DNSBL/DNSWL hit labels for an IP (empty on miss/error). */
export async function lookupDnsbl(ip: string): Promise<string[]> {
  configureDnsEnvironment()
  const reversed = reverseIpForDnsbl(ip.trim())
  if (!reversed) return []

  const hits: string[] = []
  await Promise.all([
    ...BLOCKLISTS.map(async (bl) => {
      if (await queryZone(reversed, bl.zone)) hits.push(bl.name)
    }),
    ...WHITELISTS.map(async (wl) => {
      if (await queryZone(reversed, wl.zone)) hits.push(wl.name)
    })
  ])
  return hits
}
