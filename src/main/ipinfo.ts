import { promises as dns } from 'dns'
import type { IpInfo } from '../shared/types'

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

async function resolveOne(ip: string): Promise<IpInfo> {
  const cached = ptrCache.get(ip)
  if (cached) return cached

  let ptr: string | null = null
  try {
    const names = await dns.reverse(ip)
    ptr = names[0] ?? null
  } catch {
    ptr = null
  }

  const info: IpInfo = {
    ip,
    ptr,
    provider: classifyProvider(ptr)
  }
  ptrCache.set(ip, info)
  return info
}

export async function resolveIps(ips: string[]): Promise<IpInfo[]> {
  const unique = [...new Set(ips.map((ip) => ip.trim()).filter(Boolean))]
  const results = await Promise.all(unique.map((ip) => resolveOne(ip)))
  return results
}
