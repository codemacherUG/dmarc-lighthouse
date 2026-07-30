import { promises as dns } from 'dns'
import type { IpInfo } from '../shared/types'
import { getIpEnrichment, upsertIpEnrichment } from './cache'
import { lookupCloudProvider } from './cloudranges'
import { lookupDnsbl } from './dnsbl'
import { lookupGeo } from './geoip'
import { loadSettings } from './settings'

const ptrCache = new Map<string, IpInfo>()

/** Bekannte Absender anhand PTR-/Hostname-Mustern. */
const PROVIDER_PATTERNS: Array<{ provider: string; pattern: RegExp }> = [
  { provider: 'Google', pattern: /\.(google|googlemail|gmail)\./i },
  { provider: 'Microsoft', pattern: /\.(outlook|protection\.outlook|microsoft|office365)\./i },
  { provider: 'Amazon SES', pattern: /\.(amazonaws|amazonses)\./i },
  { provider: 'Mailchimp', pattern: /\.(mailchimp|mandrillapp)\./i },
  { provider: 'SendGrid', pattern: /\.sendgrid\./i },
  { provider: 'Mailgun', pattern: /\.mailgun\./i },
  { provider: 'Postmark', pattern: /\.postmarkapp\./i },
  { provider: 'SparkPost', pattern: /\.sparkpost(mail)?\./i },
  { provider: 'Zoho', pattern: /\.zoho\./i },
  { provider: 'Yahoo', pattern: /\.yahoo\./i },
  { provider: 'Proton', pattern: /\.proton(mail)?\./i },
  { provider: 'Brevo', pattern: /\.(brevo|sendinblue)\./i },
  { provider: 'Cloudflare', pattern: /\.cloudflare\./i },
  { provider: 'OVH', pattern: /\.ovh\./i },
  { provider: 'Hetzner', pattern: /\.hetzner\./i },
  { provider: 'DigitalOcean', pattern: /\.digitalocean\./i }
]

function classifyProvider(ptr: string | null): string | null {
  if (!ptr) return null
  for (const entry of PROVIDER_PATTERNS) {
    if (entry.pattern.test(ptr)) return entry.provider
  }
  return null
}

function emptyInfo(ip: string): IpInfo {
  return {
    ip,
    ptr: null,
    provider: null,
    country: null,
    countryCode: null,
    city: null,
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
  const ptrProvider = classifyProvider(ptr)

  if (!enrichmentOn) {
    const info: IpInfo = {
      ...emptyInfo(ip),
      ptr,
      provider: ptrProvider
    }
    ptrCache.set(ip, info)
    return info
  }

  const [geo, cloudProvider, dnsblHits] = await Promise.all([
    lookupGeo(ip, { onlineFallback: Boolean(settings.geoIpOnlineFallback) }),
    settings.cloudRangesEnabled !== false ? lookupCloudProvider(ip) : Promise.resolve(null),
    settings.dnsblEnabled !== false ? lookupDnsbl(ip) : Promise.resolve([] as string[])
  ])

  const provider = cloudProvider || ptrProvider
  const info: IpInfo = {
    ip,
    ptr,
    provider,
    country: geo.country,
    countryCode: geo.countryCode,
    city: geo.city,
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
