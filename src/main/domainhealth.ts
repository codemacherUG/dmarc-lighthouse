import type { DomainHealth, DomainHealthStatus, DnsCheckResult, ReportRow } from '../shared/types'
import { buildDomainStats, mergeDomainHealth, reportsForDomainHealth } from '../shared/analyze'
import { checkDomainDns } from './dnscheck'
import { getDnsHealthCache, upsertDnsHealthCache } from './cache'
import { loadSettings } from './settings'
import { expandSpf } from './spf-expand'

async function dnsForDomain(domain: string, selectors: string[]): Promise<DnsCheckResult> {
  const cached = getDnsHealthCache(domain)
  if (cached) return cached
  const result = await checkDomainDns(domain, selectors)
  upsertDnsHealthCache(domain, result)
  return result
}

async function expandSpfCidrsForDomains(domains: string[]): Promise<string[]> {
  const cidrs = new Set<string>()
  const targets = [...new Set(domains.map((d) => d.trim().toLowerCase()).filter(Boolean))].slice(
    0,
    8
  )
  await Promise.all(
    targets.map(async (domain) => {
      try {
        const result = await expandSpf(domain)
        for (const c of result.cidrs) cidrs.add(c)
      } catch {
        // ignore per-domain failures
      }
    })
  )
  return [...cidrs]
}

/** Build multi-domain health (Ampel) for the last 14 days of the given report set. */
export async function buildDomainHealth(reports: ReportRow[]): Promise<DomainHealth[]> {
  const settings = loadSettings()
  const account = settings.accounts.find((a) => a.id === settings.activeAccountId)
  const authorized = account?.authorizedSenders ?? []
  const windowed = reportsForDomainHealth(reports)
  const spfCidrs =
    authorized.length > 0
      ? await expandSpfCidrsForDomains(windowed.map((r) => r.domain))
      : []
  const stats = buildDomainStats(windowed, authorized, spfCidrs)
  const results: DomainHealth[] = []

  // Limit concurrent DNS lookups
  const concurrency = 4
  for (let i = 0; i < stats.length; i += concurrency) {
    const chunk = stats.slice(i, i + concurrency)
    const resolved = await Promise.all(
      chunk.map(async (s) => {
        try {
          const dns = await dnsForDomain(s.domain, s.dkimSelectors)
          return mergeDomainHealth(s, dns)
        } catch {
          return mergeDomainHealth(s, null)
        }
      })
    )
    results.push(...resolved)
  }

  const order: Record<DomainHealthStatus, number> = { bad: 0, warn: 1, unknown: 2, ok: 3 }
  return results.sort((a, b) => {
    const byStatus = order[a.status] - order[b.status]
    if (byStatus !== 0) return byStatus
    return b.total - a.total
  })
}
