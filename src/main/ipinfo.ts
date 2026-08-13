import { promises as dns } from 'dns'
import { identifySender } from '../shared/sender'
import type { IpInfo } from '../shared/types'
import { getIpEnrichment, upsertIpEnrichment } from './cache'
import { lookupCloudProvider } from './cloudranges'
import { lookupDnsbl } from './dnsbl'
import { lookupGeo } from './geoip'
import { loadSettings } from './settings'

const ptrCache = new Map<string, IpInfo>()

function emptyInfo(ip: string): IpInfo {
  return {
    ip,
    ptr: null,
    provider: null,
    senderKind: null,
    country: null,
    countryCode: null,
    city: null,
    lat: null,
    lon: null,
    asn: null,
    asOrg: null,
    cloudProvider: null,
    dnsblHits: [],
    geoSource: 'none'
  }
}

async function resolvePtr(ip: string): Promise<string | null> {
  try {
    const names = await dns.reverse(ip)
    return names[0] ?? null
  } catch {
    return null
  }
}

async function resolveOne(ip: string): Promise<IpInfo> {
  const cached = ptrCache.get(ip)
  if (cached) return cached

  const settings = loadSettings().global
  const enrichmentOn = settings.enrichmentEnabled !== false

  const ptr = await resolvePtr(ip)

  if (!enrichmentOn) {
    const fromPtr = identifySender({ ptr })
    const info: IpInfo = {
      ...emptyInfo(ip),
      ptr,
      provider: fromPtr?.name ?? null,
      senderKind: fromPtr?.kind ?? null
    }
    ptrCache.set(ip, info)
    return info
  }

  const [geo, cloudProvider, dnsblHits] = await Promise.all([
    lookupGeo(ip, { onlineFallback: Boolean(settings.geoIpOnlineFallback) }),
    settings.cloudRangesEnabled !== false ? lookupCloudProvider(ip) : Promise.resolve(null),
    settings.dnsblEnabled !== false ? lookupDnsbl(ip) : Promise.resolve([] as string[])
  ])

  // The service name beats the network label: "Amazon SES" over "AWS".
  const sender = identifySender({ ptr, asOrg: geo.asOrg })
  const info: IpInfo = {
    ip,
    ptr,
    provider: sender?.name ?? cloudProvider,
    senderKind: sender?.kind ?? null,
    country: geo.country,
    countryCode: geo.countryCode,
    city: geo.city,
    lat: geo.lat,
    lon: geo.lon,
    asn: geo.asn,
    asOrg: geo.asOrg,
    cloudProvider,
    dnsblHits,
    geoSource: geo.geoSource
  }
  ptrCache.set(ip, info)
  return info
}

export async function resolveIps(ips: string[]): Promise<IpInfo[]> {
  const unique = [...new Set(ips.map((ip) => ip.trim()).filter(Boolean))]
  if (unique.length === 0) return []

  const enrichmentOn = loadSettings().global.enrichmentEnabled !== false

  if (enrichmentOn) {
    const needDb = unique.filter((ip) => !ptrCache.has(ip))
    const fromDb = needDb.length ? getIpEnrichment(needDb) : new Map<string, IpInfo>()
    for (const [ip, info] of fromDb) {
      ptrCache.set(ip, info)
    }
  }

  const missing = unique.filter((ip) => !ptrCache.has(ip))
  const fresh = await Promise.all(missing.map((ip) => resolveOne(ip)))
  if (enrichmentOn && fresh.length) {
    try {
      upsertIpEnrichment(fresh)
    } catch {
      // Persistenz ist optional
    }
  }

  return unique.map((ip) => ptrCache.get(ip) ?? emptyInfo(ip))
}

/** Clear L1 cache (e.g. after settings change). */
export function clearIpInfoMemoryCache(): void {
  ptrCache.clear()
}
