import { promises as dns } from 'dns'
import { normalizeAuthorizedSenderEntry } from '../shared/ipcidr'
import { t } from '../shared/i18n'
import type { SpfExpandResult } from '../shared/types'

const MAX_DNS_LOOKUPS = 10

function flattenTxt(records: string[][]): string[] {
  return records.map((parts) => parts.join(''))
}

/** DNS labels in SPF may include underscores (e.g. _spf.google.com). */
function isDnsName(value: string): boolean {
  return Boolean(value) && /^[a-z0-9_]([a-z0-9._-]*[a-z0-9_])?$/i.test(value)
}

/** Extract mechanisms/modifiers from a v=spf1 record (exported for tests). */
export function parseSpfTerms(record: string): string[] {
  return record
    .trim()
    .split(/\s+/)
    .map((t) => t.trim())
    .filter((t) => t && !/^v\s*=\s*spf1$/i.test(t))
}

function stripQualifier(term: string): string {
  return /^[+\-~?]/.test(term) ? term.slice(1) : term
}

/** Normalize ip4:/ip6: mechanism value to a CIDR string. */
export function spfIpMechanismToCidr(kind: 'ip4' | 'ip6', value: string): string | null {
  const raw = value.trim()
  if (!raw) return null
  if (kind === 'ip4') {
    return normalizeAuthorizedSenderEntry(raw.includes('/') ? raw : `${raw}/32`)
  }
  return normalizeAuthorizedSenderEntry(raw.includes('/') ? raw : `${raw}/128`)
}

async function resolveHostCidrs(host: string): Promise<string[]> {
  const out: string[] = []
  try {
    const v4 = await dns.resolve4(host)
    for (const ip of v4) {
      const cidr = normalizeAuthorizedSenderEntry(ip)
      if (cidr) out.push(cidr)
    }
  } catch {
    // no A records
  }
  try {
    const v6 = await dns.resolve6(host)
    for (const ip of v6) {
      const cidr = normalizeAuthorizedSenderEntry(ip)
      if (cidr) out.push(cidr)
    }
  } catch {
    // no AAAA records
  }
  return out
}

/**
 * Expand SPF for a domain into concrete IP/CIDR allowlist entries
 * (ip4/ip6/include/a/mx/redirect). Respects the RFC 10 DNS-lookup limit.
 */
export async function expandSpf(domainRaw: string): Promise<SpfExpandResult> {
  const domain = domainRaw.trim().toLowerCase().replace(/\.$/, '')
  if (!domain || !isDnsName(domain)) {
    throw new Error(t('main.invalidDomain'))
  }

  const cidrs = new Set<string>()
  const errors: string[] = []
  const visited = new Set<string>()
  let lookups = 0
  let rootRecord: string | null = null

  const addCidr = (cidr: string | null): void => {
    if (cidr) cidrs.add(cidr)
  }

  async function processDomain(name: string, isRoot: boolean): Promise<void> {
    const key = name.toLowerCase().replace(/\.$/, '')
    if (!key || visited.has(key)) return
    visited.add(key)
    if (lookups >= MAX_DNS_LOOKUPS) {
      errors.push(`DNS lookup limit (${MAX_DNS_LOOKUPS}) reached at ${key}`)
      return
    }
    lookups++

    let record: string | null = null
    try {
      const txt = flattenTxt(await dns.resolveTxt(key))
      record = txt.find((r) => /v\s*=\s*spf1/i.test(r)) ?? null
    } catch (err) {
      errors.push(`${key}: ${err instanceof Error ? err.message : String(err)}`)
      return
    }
    if (!record) {
      errors.push(`${key}: no SPF record`)
      return
    }
    if (isRoot) rootRecord = record

    let redirect: string | null = null
    for (const rawTerm of parseSpfTerms(record)) {
      const term = stripQualifier(rawTerm)
      const lower = term.toLowerCase()

      if (lower === 'all' || lower.startsWith('exp=') || lower.startsWith('exists:')) continue
      if (lower.startsWith('ptr') || lower.startsWith('ptr:')) continue

      if (lower.startsWith('redirect=')) {
        redirect = term.slice('redirect='.length).trim().toLowerCase()
        continue
      }

      if (lower.startsWith('ip4:')) {
        addCidr(spfIpMechanismToCidr('ip4', term.slice(4)))
        continue
      }
      if (lower.startsWith('ip6:')) {
        addCidr(spfIpMechanismToCidr('ip6', term.slice(4)))
        continue
      }

      if (lower.startsWith('include:')) {
        const inc = term.slice('include:'.length).trim().toLowerCase()
        if (isDnsName(inc)) {
          await processDomain(inc, false)
        }
        continue
      }

      if (lower === 'a' || lower.startsWith('a:') || lower.startsWith('a/')) {
        if (lookups >= MAX_DNS_LOOKUPS) {
          errors.push(`DNS lookup limit reached before a:${key}`)
          continue
        }
        const host =
          lower === 'a' || lower.startsWith('a/')
            ? key
            : term.slice(2).replace(/^\//, '').split('/')[0]?.trim() || key
        lookups++
        for (const c of await resolveHostCidrs(host)) addCidr(c)
        continue
      }

      if (lower === 'mx' || lower.startsWith('mx:') || lower.startsWith('mx/')) {
        if (lookups >= MAX_DNS_LOOKUPS) {
          errors.push(`DNS lookup limit reached before mx:${key}`)
          continue
        }
        const host =
          lower === 'mx' || lower.startsWith('mx/')
            ? key
            : term.slice(3).replace(/^\//, '').split('/')[0]?.trim() || key
        lookups++
        try {
          const mxs = await dns.resolveMx(host)
          for (const mx of mxs.slice(0, 10)) {
            if (lookups >= MAX_DNS_LOOKUPS) break
            lookups++
            for (const c of await resolveHostCidrs(mx.exchange)) addCidr(c)
          }
        } catch (err) {
          errors.push(`mx ${host}: ${err instanceof Error ? err.message : String(err)}`)
        }
      }
    }

    if (redirect && isDnsName(redirect)) {
      await processDomain(redirect, false)
    }
  }

  await processDomain(domain, true)

  return {
    domain,
    record: rootRecord,
    cidrs: [...cidrs].sort(),
    lookups,
    errors
  }
}
