import type { DomainHealth, DomainHealthStatus, DnsCheckResult, ReportRow } from '../shared/types'
import { buildDomainStats, mergeDomainHealth, reportsForDomainHealth } from '../shared/analyze'
import { checkDomainDns, normalizeDkimSelector } from './dnscheck'
import { getDnsHealthCache, upsertDnsHealthCache } from './cache'

async function dnsForDomain(domain: string, selectors: string[]): Promise<DnsCheckResult> {
  const cached = getDnsHealthCache(domain)
  const requestedSelectors = selectors
    .map(normalizeDkimSelector)
    .filter((selector): selector is string => Boolean(selector))
    .sort()
  const cachedSelectors = cached?.dkim.selectors.map(({ selector }) => selector).sort() ?? []
  const cachedMissingDkim = cached?.dkim.selectors.some(({ found }) => !found) ?? false
  if (cached && !cachedMissingDkim && requestedSelectors.join('|') === cachedSelectors.join('|')) {
    return cached
  }
  const result = await checkDomainDns(domain, selectors)
  upsertDnsHealthCache(domain, result)
  return result
}

/** Build multi-domain health (Ampel) for the last 14 days of the given report set. */
export async function buildDomainHealth(reports: ReportRow[]): Promise<DomainHealth[]> {
  const windowed = reportsForDomainHealth(reports)
  const stats = buildDomainStats(windowed)
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
