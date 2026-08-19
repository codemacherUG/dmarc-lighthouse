/**
 * Recipient-side email scanners (Check Point Harmony, …) that show up as
 * source IPs in DMARC reports. Matched against PTR hostnames or explicit IPs.
 *
 * Lines are domain suffixes by default (`cloud-sec-av.com` matches
 * `mail.eu.cloud-sec-av.com`). `/pattern/flags` is an opt-in regex.
 * Bare IPv4/IPv6 addresses match that source IP only.
 */

import { organizationalDomain, normalizeHost as normalizeDomainHost } from './domain'
import { ipSortKey } from './ipcidr'
import type { SenderKind } from './sender'

/** Shipped default: Check Point Harmony / Avanan re-injection hosts. */
export const DEFAULT_SCANNER_NOISE_HOSTS = 'cloud-sec-av.com'

export type ScannerNoiseMatcher =
  | { kind: 'suffix'; value: string }
  | { kind: 'regex'; value: RegExp }
  | { kind: 'ip'; value: string }

function normalizeHost(value: string): string {
  return value.trim().toLowerCase().replace(/\.$/, '')
}

function normalizeIpLiteral(value: string): string | null {
  const s = value.trim()
  if (!s || ipSortKey(s) == null) return null
  return s.toLowerCase()
}

/** DNS-label suffix: `cloud-sec-av.com` matches subdomains, not `notcloud-sec-av.com`. */
export function hostHasDomainSuffix(host: string, suffix: string): boolean {
  const h = normalizeHost(host)
  const s = normalizeHost(suffix)
  if (!h || !s || !s.includes('.')) return false
  if (h === s) return true
  const hostLabels = h.split('.')
  const suffixLabels = s.split('.')
  if (suffixLabels.length > hostLabels.length) return false
  const start = hostLabels.length - suffixLabels.length
  return suffixLabels.every((label, i) => hostLabels[start + i] === label)
}

function parseRegexLiteral(line: string): RegExp | null {
  if (line.length < 2 || !line.startsWith('/')) return null
  const last = line.lastIndexOf('/')
  if (last <= 0) return null
  const body = line.slice(1, last)
  const flags = line.slice(last + 1)
  if (!body) return null
  if (flags && !/^[gimsuy]*$/.test(flags)) return null
  try {
    const nextFlags = flags.includes('i') ? flags : `${flags}i`
    return new RegExp(body, nextFlags)
  } catch {
    return null
  }
}

function normalizeSuffix(line: string): string | null {
  let s = line.trim()
  if (!s) return null
  s = s.replace(/^https?:\/\//i, '')
  const slash = s.indexOf('/')
  if (slash >= 0) s = s.slice(0, slash)
  s = normalizeHost(s).replace(/^\*\./, '')
  if (!s.includes('.') || s.startsWith('.')) return null
  if (!/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/.test(s)) {
    return null
  }
  return s
}

/** Parse the settings textarea: suffixes, optional `/regex/`, `#` comments. */
export function parseScannerNoiseHosts(text: string): ScannerNoiseMatcher[] {
  const matchers: ScannerNoiseMatcher[] = []
  const seen = new Set<string>()
  for (const raw of text.split(/\n/)) {
    const line = raw.trim()
    if (!line || line.startsWith('#')) continue
    if (line.startsWith('/')) {
      const re = parseRegexLiteral(line)
      if (!re) continue
      const key = `re:${re.source}:${re.flags}`
      if (seen.has(key)) continue
      seen.add(key)
      matchers.push({ kind: 'regex', value: re })
      continue
    }
    for (const part of line.split(/[,;]+/)) {
      const ip = normalizeIpLiteral(part)
      if (ip) {
        const key = `ip:${ip}`
        if (seen.has(key)) continue
        seen.add(key)
        matchers.push({ kind: 'ip', value: ip })
        continue
      }
      const suffix = normalizeSuffix(part)
      if (!suffix) continue
      const key = `sfx:${suffix}`
      if (seen.has(key)) continue
      seen.add(key)
      matchers.push({ kind: 'suffix', value: suffix })
    }
  }
  return matchers
}

export function hostMatchesScannerNoise(
  host: string | null | undefined,
  matchers: readonly ScannerNoiseMatcher[]
): boolean {
  if (!host?.trim() || matchers.length === 0) return false
  const h = normalizeHost(host)
  for (const matcher of matchers) {
    if (matcher.kind === 'suffix') {
      if (hostHasDomainSuffix(h, matcher.value)) return true
    } else if (matcher.kind === 'regex' && matcher.value.test(h)) {
      return true
    }
  }
  return false
}

export function ipMatchesScannerNoise(
  ip: string | null | undefined,
  matchers: readonly ScannerNoiseMatcher[]
): boolean {
  const normalized = ip ? normalizeIpLiteral(ip) : null
  if (!normalized || matchers.length === 0) return false
  return matchers.some((matcher) => matcher.kind === 'ip' && matcher.value === normalized)
}

/** True when the source IP is listed or its PTR matches a host suffix / regex. */
export function matchesScannerNoise(
  ip: string | null | undefined,
  ptr: string | null | undefined,
  matchers: readonly ScannerNoiseMatcher[]
): boolean {
  return ipMatchesScannerNoise(ip, matchers) || hostMatchesScannerNoise(ptr, matchers)
}

/**
 * What to append for this sender: gateway org-domain, else the PTR host, else the IP.
 * Avoids turning generic cloud PTRs (amazonaws.com) into a blanket suffix.
 */
export function suggestScannerNoiseEntry(
  ptr: string | null | undefined,
  ip: string,
  senderKind?: SenderKind | null
): string | null {
  const org = organizationalDomain(ptr)
  if (org && senderKind === 'gateway') return org
  const host = normalizeDomainHost(ptr)
  if (host?.includes('.')) return host
  return normalizeIpLiteral(ip)
}

/** True when `entry` is already covered by the parsed list. */
export function scannerNoiseEntryCovered(
  entry: string,
  matchers: readonly ScannerNoiseMatcher[]
): boolean {
  if (ipMatchesScannerNoise(entry, matchers)) return true
  return hostMatchesScannerNoise(entry, matchers)
}

/** Append a host or IP; no-op when the entry is empty or already covered. */
export function appendScannerNoiseEntry(text: string, entry: string): string {
  const value = entry.trim()
  if (!value) return text
  if (scannerNoiseEntryCovered(value, parseScannerNoiseHosts(text))) return text
  const trimmed = text.replace(/\s+$/, '')
  return trimmed ? `${trimmed}\n${value}` : value
}
