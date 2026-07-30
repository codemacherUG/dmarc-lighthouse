import type { RdapInfo } from '../shared/types'
import { t } from '../shared/i18n'

interface RdapEntity {
  roles?: string[]
  vcardArray?: unknown
  handle?: string
}

interface RdapResponse {
  name?: string
  handle?: string
  country?: string
  startAddress?: string
  endAddress?: string
  cidr0_cidrs?: Array<{ v4prefix?: string; v6prefix?: string; length?: number }>
  entities?: RdapEntity[]
  remarks?: Array<{ description?: string[] }>
  errorCode?: number
  title?: string
}

function extractOrg(data: RdapResponse): string | null {
  if (data.name) return data.name
  for (const ent of data.entities ?? []) {
    const roles = ent.roles ?? []
    if (roles.includes('registrant') || roles.includes('administrative')) {
      const fn = vcardFn(ent.vcardArray)
      if (fn) return fn
    }
  }
  for (const ent of data.entities ?? []) {
    const fn = vcardFn(ent.vcardArray)
    if (fn) return fn
  }
  return data.handle ?? null
}

function vcardFn(vcardArray: unknown): string | null {
  if (!Array.isArray(vcardArray) || vcardArray[0] !== 'vcard') return null
  const cards = vcardArray[1]
  if (!Array.isArray(cards)) return null
  for (const row of cards) {
    if (Array.isArray(row) && row[0] === 'fn' && typeof row[3] === 'string') return row[3]
  }
  return null
}

function extractAbuseEmail(data: RdapResponse): string | null {
  for (const ent of data.entities ?? []) {
    if (!(ent.roles ?? []).includes('abuse')) continue
    const email = vcardEmail(ent.vcardArray)
    if (email) return email
  }
  for (const ent of data.entities ?? []) {
    const email = vcardEmail(ent.vcardArray)
    if (email && /abuse/i.test(email)) return email
  }
  return null
}

function vcardEmail(vcardArray: unknown): string | null {
  if (!Array.isArray(vcardArray) || vcardArray[0] !== 'vcard') return null
  const cards = vcardArray[1]
  if (!Array.isArray(cards)) return null
  for (const row of cards) {
    if (Array.isArray(row) && row[0] === 'email' && typeof row[3] === 'string') return row[3]
  }
  return null
}

function extractCidr(data: RdapResponse): string | null {
  const c0 = data.cidr0_cidrs?.[0]
  if (c0?.v4prefix != null && c0.length != null) return `${c0.v4prefix}/${c0.length}`
  if (c0?.v6prefix != null && c0.length != null) return `${c0.v6prefix}/${c0.length}`
  if (data.startAddress && data.endAddress) return `${data.startAddress} - ${data.endAddress}`
  return null
}

/** On-demand RDAP lookup via rdap.org bootstrap. */
export async function lookupRdap(ipRaw: string): Promise<RdapInfo> {
  const ip = ipRaw.trim()
  if (!ip) {
    return {
      ip: '',
      org: null,
      country: null,
      cidr: null,
      abuseEmail: null,
      rawSummary: null,
      error: t('enrichment.rdapInvalidIp')
    }
  }

  try {
    const res = await fetch(`https://rdap.org/ip/${encodeURIComponent(ip)}`, {
      headers: { Accept: 'application/rdap+json, application/json' },
      signal: AbortSignal.timeout(10_000),
      redirect: 'follow'
    })
    if (!res.ok) {
      return {
        ip,
        org: null,
        country: null,
        cidr: null,
        abuseEmail: null,
        rawSummary: null,
        error: t('enrichment.rdapHttpError', { status: String(res.status) })
      }
    }
    const data = (await res.json()) as RdapResponse
    if (data.errorCode) {
      return {
        ip,
        org: null,
        country: null,
        cidr: null,
        abuseEmail: null,
        rawSummary: null,
        error: data.title || String(data.errorCode)
      }
    }

    const org = extractOrg(data)
    const country = data.country ?? null
    const cidr = extractCidr(data)
    const abuseEmail = extractAbuseEmail(data)
    const parts = [
      org && `Org: ${org}`,
      country && `Country: ${country}`,
      cidr && `CIDR: ${cidr}`,
      abuseEmail && `Abuse: ${abuseEmail}`
    ].filter(Boolean)

    return {
      ip,
      org,
      country,
      cidr,
      abuseEmail,
      rawSummary: parts.join(' · ') || null
    }
  } catch (err) {
    return {
      ip,
      org: null,
      country: null,
      cidr: null,
      abuseEmail: null,
      rawSummary: null,
      error: err instanceof Error ? err.message : String(err)
    }
  }
}
