import { promises as dns } from 'dns'
import type { DkimSelectorCheck, DnsCheckResult } from '../shared/types'
import { t } from '../shared/i18n'

function flattenTxt(records: string[][]): string[] {
  return records.map((parts) => parts.join(''))
}

function parseDmarcPolicy(records: string[]): {
  policy: string | null
  rua: string | null
  ruf: string | null
} {
  const joined = records.find((r) => /v\s*=\s*DMARC1/i.test(r)) ?? records[0] ?? ''
  const policyMatch = joined.match(/(?:^|;)\s*p\s*=\s*([^;\s]+)/i)
  const ruaMatch = joined.match(/(?:^|;)\s*rua\s*=\s*([^;]+)/i)
  const rufMatch = joined.match(/(?:^|;)\s*ruf\s*=\s*([^;]+)/i)
  return {
    policy: policyMatch?.[1]?.trim() ?? null,
    rua: ruaMatch?.[1]?.trim() ?? null,
    ruf: rufMatch?.[1]?.trim() ?? null
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

async function checkDkimSelector(domain: string, selector: string): Promise<DkimSelectorCheck> {
  try {
    const txt = flattenTxt(await dns.resolveTxt(`${selector}._domainkey.${domain}`))
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

export async function checkDomainDns(
  domainRaw: string,
  selectorsRaw: string[] = []
): Promise<DnsCheckResult> {
  const domain = domainRaw.trim().toLowerCase().replace(/\.$/, '')
  if (!domain || !/^[a-z0-9.-]+$/i.test(domain)) {
    throw new Error(t('main.invalidDomain'))
  }

  const selectors = [
    ...new Set((selectorsRaw ?? []).map(normalizeDkimSelector).filter((s): s is string => Boolean(s)))
  ].slice(0, 10)

  const checkedAt = new Date().toISOString()
  const result: DnsCheckResult = {
    domain,
    dmarc: { found: false, records: [], policy: null, rua: null, ruf: null },
    spf: { found: false, records: [] },
    dkim: { selectors: [] },
    checkedAt
  }

  try {
    const dmarcTxt = flattenTxt(await dns.resolveTxt(`_dmarc.${domain}`))
    result.dmarc.records = dmarcTxt
    result.dmarc.found = dmarcTxt.some((r) => /v\s*=\s*DMARC1/i.test(r))
    const parsed = parseDmarcPolicy(dmarcTxt)
    result.dmarc.policy = parsed.policy
    result.dmarc.rua = parsed.rua
    result.dmarc.ruf = parsed.ruf
  } catch (err) {
    result.dmarc.error = err instanceof Error ? err.message : String(err)
  }

  try {
    const txt = flattenTxt(await dns.resolveTxt(domain))
    const spf = txt.filter((r) => /v\s*=\s*spf1/i.test(r))
    result.spf.records = spf
    result.spf.found = spf.length > 0
  } catch (err) {
    result.spf.error = err instanceof Error ? err.message : String(err)
  }

  result.dkim.selectors = await Promise.all(selectors.map((sel) => checkDkimSelector(domain, sel)))

  return result
}
