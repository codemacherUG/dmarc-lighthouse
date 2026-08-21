import { isAuthorizedSender, parseCidr } from './ipcidr'

/**
 * Lifecycle of a recognized sending service (provider) for one of your domains.
 * `known` suppresses "new source" alerts; everything else still alerts, because
 * `retired` reappearing or `investigate` continuing is itself the interesting event.
 */
export type SendingServiceStatus = 'known' | 'unknown' | 'retired' | 'investigate'

/**
 * A persistent inventory entry: "Microsoft 365 sends for example.de" rather than
 * a specific, ever-changing cloud IP. Scope narrows via domain/CIDR/ASN, all optional.
 */
export interface SendingService {
  id: string
  /** Sending service name, matches `IpInfo.provider` (e.g. "Microsoft 365", "Amazon SES"). */
  provider: string
  /** Header-From domain(s) this entry applies to, comma/newline separated; empty/null = every domain. */
  domain: string | null
  /** Optional comma/newline-separated CIDRs narrowing the match to specific networks. */
  cidr: string | null
  /** Optional AS number narrowing the match. */
  asn: number | null
  status: SendingServiceStatus
  note: string | null
  team: string | null
  createdAt: string
  updatedAt: string
}

export type SendingServiceInput = Omit<SendingService, 'id' | 'createdAt' | 'updatedAt'> & {
  id?: string
}

/** One newly observed (provider, domain) pairing in a single fetch, grouped for alerting. */
export interface NewSendingSourceGroup {
  provider: string | null
  domain: string | null
  ips: string[]
  status: SendingServiceStatus
  /** AS number shared by every IP in the group, or null when absent/mixed. */
  asn: number | null
}

function normalizeDomain(domain: string | null | undefined): string {
  return (domain ?? '').trim().toLowerCase()
}

/** Splits a comma/newline separated domain list into normalized, non-empty domains. */
export function parseDomainList(raw: string | null | undefined): string[] {
  return (raw ?? '')
    .split(/[,\n]/)
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean)
}

/**
 * Best-matching inventory entry for a sending IP, scoped by provider, domain, CIDR and ASN.
 * More specific entries (domain + network/ASN) win over provider-only entries. When PTR/ASN
 * detection found no provider name, only a network-scoped entry (CIDR and/or ASN) can still
 * vouch for the IP — a bare provider label has nothing to compare against in that case.
 */
export function matchSendingService(
  services: readonly SendingService[],
  input: { provider: string | null; domain: string | null; ip: string; asn?: number | null }
): SendingService | null {
  const provider = input.provider ? input.provider.trim().toLowerCase() : null
  const domain = normalizeDomain(input.domain)
  let best: SendingService | null = null
  let bestScore = -1
  for (const svc of services) {
    if (provider) {
      if (svc.provider.trim().toLowerCase() !== provider) continue
    } else if (!svc.cidr && svc.asn == null) {
      continue
    }
    const svcDomains = parseDomainList(svc.domain)
    if (svcDomains.length > 0 && !svcDomains.includes(domain)) continue
    if (svc.asn != null && svc.asn !== input.asn) continue
    if (svc.cidr) {
      const prefixes = svc.cidr
        .split(/[,\n]/)
        .map((cidr) => parseCidr(svc.provider, cidr.trim()))
        .filter((prefix) => prefix != null)
      if (!prefixes.length || !isAuthorizedSender(input.ip, prefixes)) continue
    }
    let score = 0
    if (svcDomains.length > 0) score += 2
    if (svc.cidr) score += 1
    if (svc.asn != null) score += 1
    if (score > bestScore) {
      best = svc
      bestScore = score
    }
  }
  return best
}

/**
 * Groups newly observed source IPs by (provider, domain) and resolves each group's
 * inventory status. `unknown` covers both "no inventory entry" and unrecognized providers.
 */
export function groupNewSendingSources(
  entries: ReadonlyArray<{
    ip: string
    provider: string | null
    domain: string | null
    asn?: number | null
  }>,
  services: readonly SendingService[]
): NewSendingSourceGroup[] {
  const groups = new Map<string, NewSendingSourceGroup>()
  for (const entry of entries) {
    const match = matchSendingService(services, entry)
    const status = match?.status ?? 'unknown'
    const key = `${(entry.provider ?? '').toLowerCase()}\u0000${normalizeDomain(entry.domain)}\u0000${status}`
    let group = groups.get(key)
    if (!group) {
      group = {
        provider: entry.provider,
        domain: entry.domain,
        ips: [],
        status,
        asn: entry.asn ?? null
      }
      groups.set(key, group)
    } else if (group.asn !== (entry.asn ?? null)) {
      // Mixed ASNs across the group's IPs — no single value to suggest.
      group.asn = null
    }
    if (!group.ips.includes(entry.ip)) group.ips.push(entry.ip)
  }
  return [...groups.values()]
}

/** Groups worth alerting on: anything not already inventoried as `known`. */
export function alertableSendingSources(
  groups: readonly NewSendingSourceGroup[]
): NewSendingSourceGroup[] {
  return groups.filter((g) => g.status !== 'known' && g.ips.length > 0)
}
