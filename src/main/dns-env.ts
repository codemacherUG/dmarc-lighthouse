import dns, { promises as dnsPromises } from 'node:dns'

/** Public recursive resolvers used when the OS list is empty or unusable. */
export const PUBLIC_DNS_FALLBACK = ['1.1.1.1', '8.8.8.8'] as const

const DEFAULT_DNS_TIMEOUT_MS = 5_000

let configured = false

/** Strip Windows/zone-id suffixes (`fe80::1%12`). */
export function normalizeDnsServer(server: string): string {
  return server.trim().replace(/%.*$/, '')
}

/**
 * Drop resolvers that routinely hang Node/c-ares on Windows:
 * link-local IPv6, deprecated site-local (fec0::/10), and wildcard binds.
 */
export function isUsableDnsServer(server: string): boolean {
  const s = normalizeDnsServer(server).toLowerCase()
  if (!s) return false
  if (s === '0.0.0.0' || s === '::' || s === '[::]') return false
  // fe80::/10 link-local + fec0::/10 deprecated site-local (common Win10 leftovers)
  if (/^fe[89a-f][0-9a-f]:/i.test(s)) return false
  return true
}

/** Prefer IPv4, then usable IPv6; fall back to public resolvers. */
export function pickDnsServers(servers: string[] = dns.getServers()): string[] {
  const usable = [
    ...new Set(servers.map(normalizeDnsServer).filter(isUsableDnsServer))
  ]
  const v4 = usable.filter((s) => !s.includes(':'))
  const v6 = usable.filter((s) => s.includes(':'))
  const ordered = [...v4, ...v6]
  return ordered.length ? ordered : [...PUBLIC_DNS_FALLBACK]
}

/**
 * Once per process: prefer IPv4 results and replace a broken OS resolver list
 * (common on Windows 10 with leftover fec0::/fe80:: DNS entries).
 */
export function configureDnsEnvironment(): void {
  if (configured) return
  configured = true
  try {
    dns.setDefaultResultOrder('ipv4first')
  } catch {
    // older Node / unsupported
  }
  try {
    const current = dns.getServers().map(normalizeDnsServer)
    const picked = pickDnsServers(current)
    if (picked.join('|') !== current.join('|')) {
      dns.setServers(picked)
    }
  } catch {
    try {
      dns.setServers([...PUBLIC_DNS_FALLBACK])
    } catch {
      // ignore
    }
  }
}

/** Reset for tests. */
export function resetDnsEnvironmentForTests(): void {
  configured = false
}

export async function withDnsTimeout<T>(
  promise: Promise<T>,
  ms = DEFAULT_DNS_TIMEOUT_MS
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => reject(Object.assign(new Error('DNS timeout'), { code: 'ETIMEOUT' })), ms)
      })
    ])
  } finally {
    if (timer) clearTimeout(timer)
  }
}

function dnsCode(err: unknown): string {
  if (err && typeof err === 'object' && 'code' in err) {
    return String((err as { code?: unknown }).code ?? '')
  }
  return ''
}

/** NXDOMAIN / empty — do not retry on a different resolver. */
export function isEmptyDnsError(err: unknown): boolean {
  const code = dnsCode(err)
  return code === 'ENOTFOUND' || code === 'ENODATA' || code === 'ENONAME'
}

type PromiseResolver = InstanceType<typeof dnsPromises.Resolver>

function createFallbackResolver(): PromiseResolver {
  const resolver = new dnsPromises.Resolver()
  resolver.setServers([...PUBLIC_DNS_FALLBACK])
  return resolver
}

async function withPublicFallback<T>(
  primary: () => Promise<T>,
  fallback: (resolver: PromiseResolver) => Promise<T>
): Promise<T> {
  configureDnsEnvironment()
  try {
    return await withDnsTimeout(primary())
  } catch (err) {
    if (isEmptyDnsError(err)) throw err
    return await withDnsTimeout(fallback(createFallbackResolver()))
  }
}

export async function resolveTxtReliable(name: string): Promise<string[][]> {
  return withPublicFallback(
    () => dnsPromises.resolveTxt(name),
    (r) => r.resolveTxt(name)
  )
}

export async function resolveCnameReliable(name: string): Promise<string[]> {
  return withPublicFallback(
    () => dnsPromises.resolveCname(name),
    (r) => r.resolveCname(name)
  )
}

export async function resolveNsReliable(name: string): Promise<string[]> {
  return withPublicFallback(
    () => dnsPromises.resolveNs(name),
    (r) => r.resolveNs(name)
  )
}

export async function resolve4Reliable(name: string): Promise<string[]> {
  return withPublicFallback(
    () => dnsPromises.resolve4(name),
    (r) => r.resolve4(name)
  )
}

export async function resolve6Reliable(name: string): Promise<string[]> {
  return withPublicFallback(
    () => dnsPromises.resolve6(name),
    (r) => r.resolve6(name)
  )
}

export async function resolveMxReliable(
  name: string
): Promise<Array<{ exchange: string; priority: number }>> {
  return withPublicFallback(
    () => dnsPromises.resolveMx(name),
    (r) => r.resolveMx(name)
  )
}

export async function reverseReliable(ip: string): Promise<string[]> {
  return withPublicFallback(
    () => dnsPromises.reverse(ip),
    (r) => r.reverse(ip)
  )
}

/** Authoritative resolver aimed at specific NS IPs (already resolved by caller). */
export function createResolverForServers(
  servers: string[]
): InstanceType<typeof dnsPromises.Resolver> {
  const resolver = new dnsPromises.Resolver()
  const normalized = [...new Set(servers.map(normalizeDnsServer).filter(Boolean))]
  const usable = normalized.filter(isUsableDnsServer)
  // Prefer filtered list; if everything looks "unusable" keep the originals
  // rather than silently rewriting auth queries to public recursive resolvers.
  const list = usable.length ? usable : normalized
  if (!list.length) {
    resolver.setServers([...PUBLIC_DNS_FALLBACK])
  } else {
    resolver.setServers(list)
  }
  return resolver
}
