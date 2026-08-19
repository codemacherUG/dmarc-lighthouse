import {
  bimiHost,
  DEFAULT_BIMI_SELECTOR,
  isValidBimiSelector,
  normalizeBimiSelector,
  parseBimiRecord
} from '../shared/bimi-builder'
import type {
  BimiCheckResult,
  DkimSelectorCheck,
  DnsCheckResult,
  DnsResolverInfo
} from '../shared/types'
import { t } from '../shared/i18n'
import {
  configureDnsEnvironment,
  createResolverForServers,
  isEmptyDnsError,
  resolve4Reliable,
  resolve6Reliable,
  resolveNsReliable,
  resolveTxtReliable,
  withDnsTimeout
} from './dns-env'

function flattenTxt(records: string[][]): string[] {
  return records.map((parts) => parts.join(''))
}

export function parseDmarcPolicy(records: string[]): {
  policy: string | null
  rua: string | null
  ruf: string | null
  testing: boolean
  np: string | null
  psd: boolean
} {
  const joined = records.find((r) => /v\s*=\s*DMARC1/i.test(r)) ?? records[0] ?? ''
  const policyMatch = joined.match(/(?:^|;)\s*p\s*=\s*([^;\s]+)/i)
  const ruaMatch = joined.match(/(?:^|;)\s*rua\s*=\s*([^;]+)/i)
  const rufMatch = joined.match(/(?:^|;)\s*ruf\s*=\s*([^;]+)/i)
  const tMatch = joined.match(/(?:^|;)\s*t\s*=\s*([^;\s]+)/i)
  const npMatch = joined.match(/(?:^|;)\s*np\s*=\s*([^;\s]+)/i)
  const psdMatch = joined.match(/(?:^|;)\s*psd\s*=\s*([^;\s]+)/i)
  return {
    policy: policyMatch?.[1]?.trim() ?? null,
    rua: ruaMatch?.[1]?.trim() ?? null,
    ruf: rufMatch?.[1]?.trim() ?? null,
    // RFC 9989: t=y marks a testing rollout stage.
    testing: (tMatch?.[1]?.trim() ?? '').toLowerCase() === 'y',
    np: npMatch?.[1]?.trim() ?? null,
    psd: (psdMatch?.[1]?.trim() ?? '').toLowerCase() === 'y'
  }
}

/**
 * Accept selector, `selector._domainkey`, or a full DKIM hostname.
 * Lookup always uses `{selector}._domainkey.{domain}`.
 */
export function normalizeDkimSelector(raw: string): string | null {
  let s = raw.trim().toLowerCase().replace(/\.+$/, '')
  if (!s) return null
  const marker = '._domainkey'
  const idx = s.indexOf(marker)
  if (idx >= 0) s = s.slice(0, idx)
  if (!s || !/^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/.test(s)) return null
  return s
}

/** Zones to try for NS, longest first. Stops before the TLD (single label). */
export function ancestorZones(domain: string): string[] {
  const labels = domain.toLowerCase().replace(/\.+$/, '').split('.').filter(Boolean)
  const zones: string[] = []
  for (let i = 0; i <= labels.length - 2; i++) {
    zones.push(labels.slice(i).join('.'))
  }
  return zones
}

async function resolveHostIps(host: string): Promise<string[]> {
  const settled = await Promise.allSettled([resolve4Reliable(host), resolve6Reliable(host)])
  const ips: string[] = []
  for (const item of settled) {
    if (item.status === 'fulfilled') ips.push(...item.value)
  }
  return ips
}

type AuthResolver = ReturnType<typeof createResolverForServers>

export interface AuthoritativeNs {
  zone: string
  names: string[]
  servers: string[]
}

/** Find NS for the domain or a parent zone, then resolve those names to IPs. */
export async function findAuthoritativeNs(domain: string): Promise<AuthoritativeNs | null> {
  configureDnsEnvironment()
  for (const zone of ancestorZones(domain)) {
    try {
      const names = [
        ...new Set((await resolveNsReliable(zone)).map((n) => n.replace(/\.$/, '').toLowerCase()))
      ]
      if (names.length === 0) continue
      const servers: string[] = []
      for (const name of names) {
        for (const ip of await resolveHostIps(name)) {
          if (!servers.includes(ip)) servers.push(ip)
        }
        if (servers.length >= 6) break
      }
      if (servers.length > 0) return { zone, names, servers }
    } catch {
      continue
    }
  }
  return null
}

async function resolveTxtRecords(name: string, auth: AuthResolver | null): Promise<string[][]> {
  if (auth) {
    try {
      return await withDnsTimeout(auth.resolveTxt(name))
    } catch (err) {
      if (isEmptyDnsError(err)) throw err
    }
  }
  return resolveTxtReliable(name)
}

/**
 * RFC 9989 policy discovery: try `_dmarc.{domain}` first, then walk up the ancestor
 * zones until a record is found. `treeWalked` is true once we leave the exact domain.
 */
export async function discoverDmarcRecords(
  domain: string,
  auth: AuthResolver | null
): Promise<{ zone: string; records: string[]; treeWalked: boolean; error?: string }> {
  let lastError: string | undefined
  for (const [index, zone] of ancestorZones(domain).entries()) {
    try {
      const records = flattenTxt(await resolveTxtRecords(`_dmarc.${zone}`, auth))
      if (records.some((r) => /v\s*=\s*DMARC1/i.test(r))) {
        return { zone, records, treeWalked: index > 0 }
      }
    } catch (err) {
      if (!isEmptyDnsError(err)) lastError = err instanceof Error ? err.message : String(err)
    }
  }
  return { zone: domain, records: [], treeWalked: false, error: lastError }
}

async function checkDkimSelector(
  domain: string,
  selector: string,
  auth: AuthResolver | null
): Promise<DkimSelectorCheck> {
  try {
    const txt = flattenTxt(await resolveTxtRecords(`${selector}._domainkey.${domain}`, auth))
    const record = txt.find((r) => /v\s*=\s*DKIM1/i.test(r) || /(?:^|;)\s*p\s*=/i.test(r)) ?? null
    return { selector, found: record != null, record }
  } catch (err) {
    return {
      selector,
      found: false,
      record: null,
      error: err instanceof Error ? err.message : String(err)
    }
  }
}

async function lookupBimi(
  domain: string,
  selector: string,
  auth: AuthResolver | null
): Promise<BimiCheckResult> {
  const host = bimiHost(domain, selector)
  const empty: BimiCheckResult = {
    domain,
    selector,
    host,
    found: false,
    records: [],
    location: null,
    authority: null
  }
  try {
    const records = flattenTxt(await resolveTxtRecords(host, auth))
    const parsed =
      records.map(parseBimiRecord).find((r) => r.found) ?? parseBimiRecord(records[0] ?? '')
    return {
      ...empty,
      found: parsed.found,
      records,
      location: parsed.location,
      authority: parsed.authority
    }
  } catch (err) {
    if (isEmptyDnsError(err)) return empty
    return { ...empty, error: err instanceof Error ? err.message : String(err) }
  }
}

export async function checkDomainDns(
  domainRaw: string,
  selectorsRaw: string[] = []
): Promise<DnsCheckResult> {
  configureDnsEnvironment()
  const domain = domainRaw.trim().toLowerCase().replace(/\.$/, '')
  if (!domain || !/^[a-z0-9.-]+$/i.test(domain)) {
    throw new Error(t('main.invalidDomain'))
  }

  const selectors = [
    ...new Set(
      (selectorsRaw ?? []).map(normalizeDkimSelector).filter((s): s is string => Boolean(s))
    )
  ].slice(0, 10)

  const authNs = await findAuthoritativeNs(domain)
  let auth: AuthResolver | null = null
  const resolver: DnsResolverInfo = authNs
    ? { mode: 'authoritative', zone: authNs.zone, nameservers: authNs.names }
    : { mode: 'recursive', zone: null, nameservers: [] }
  if (authNs) {
    auth = createResolverForServers(authNs.servers)
  }

  const checkedAt = new Date().toISOString()
  const result: DnsCheckResult = {
    domain,
    dmarc: { found: false, records: [], policy: null, rua: null, ruf: null },
    spf: { found: false, records: [] },
    dkim: { selectors: [] },
    resolver,
    checkedAt
  }

  try {
    const discovered = await discoverDmarcRecords(domain, auth)
    result.dmarc.records = discovered.records
    result.dmarc.found = discovered.records.some((r) => /v\s*=\s*DMARC1/i.test(r))
    result.dmarc.host = `_dmarc.${discovered.zone}`
    result.dmarc.treeWalked = discovered.treeWalked
    const parsed = parseDmarcPolicy(discovered.records)
    result.dmarc.policy = parsed.policy
    result.dmarc.rua = parsed.rua
    result.dmarc.ruf = parsed.ruf
    result.dmarc.testing = parsed.testing
    result.dmarc.np = parsed.np
    result.dmarc.psd = parsed.psd
    if (discovered.error && !result.dmarc.found) result.dmarc.error = discovered.error
  } catch (err) {
    result.dmarc.error = err instanceof Error ? err.message : String(err)
  }

  try {
    const txt = flattenTxt(await resolveTxtRecords(domain, auth))
    const spf = txt.filter((r) => /v\s*=\s*spf1/i.test(r))
    result.spf.records = spf
    result.spf.found = spf.length > 0
  } catch (err) {
    result.spf.error = err instanceof Error ? err.message : String(err)
  }

  const [dkimSelectors, bimi] = await Promise.all([
    Promise.all(selectors.map((sel) => checkDkimSelector(domain, sel, auth))),
    lookupBimi(domain, DEFAULT_BIMI_SELECTOR, auth)
  ])
  result.dkim.selectors = dkimSelectors
  result.bimi = bimi

  return result
}

export async function checkBimiDns(
  domainRaw: string,
  selectorRaw = DEFAULT_BIMI_SELECTOR
): Promise<BimiCheckResult> {
  configureDnsEnvironment()
  const domain = domainRaw.trim().toLowerCase().replace(/\.$/, '')
  if (!domain || !/^[a-z0-9.-]+$/i.test(domain)) {
    throw new Error(t('main.invalidDomain'))
  }
  const selector = isValidBimiSelector(selectorRaw)
    ? normalizeBimiSelector(selectorRaw)
    : DEFAULT_BIMI_SELECTOR

  const authNs = await findAuthoritativeNs(domain)
  let auth: AuthResolver | null = null
  if (authNs) {
    auth = createResolverForServers(authNs.servers)
  }

  return lookupBimi(domain, selector, auth)
}
