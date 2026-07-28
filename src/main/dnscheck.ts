import { promises as dns } from 'dns'
import type { DnsCheckResult } from '../shared/types'

function flattenTxt(records: string[][]): string[] {
  return records.map((parts) => parts.join(''))
}

function parseDmarcPolicy(records: string[]): { policy: string | null; rua: string | null } {
  const joined = records.find((r) => /v\s*=\s*DMARC1/i.test(r)) ?? records[0] ?? ''
  const policyMatch = joined.match(/(?:^|;)\s*p\s*=\s*([^;\s]+)/i)
  const ruaMatch = joined.match(/(?:^|;)\s*rua\s*=\s*([^;]+)/i)
  return {
    policy: policyMatch?.[1]?.trim() ?? null,
    rua: ruaMatch?.[1]?.trim() ?? null
  }
}

export async function checkDomainDns(domainRaw: string): Promise<DnsCheckResult> {
  const domain = domainRaw.trim().toLowerCase().replace(/\.$/, '')
  if (!domain || !/^[a-z0-9.-]+$/i.test(domain)) {
    throw new Error('Ungültige Domain.')
  }

  const checkedAt = new Date().toISOString()
  const result: DnsCheckResult = {
    domain,
    dmarc: { found: false, records: [], policy: null, rua: null },
    spf: { found: false, records: [] },
    checkedAt
  }

  try {
    const dmarcTxt = flattenTxt(await dns.resolveTxt(`_dmarc.${domain}`))
    result.dmarc.records = dmarcTxt
    result.dmarc.found = dmarcTxt.some((r) => /v\s*=\s*DMARC1/i.test(r))
    const parsed = parseDmarcPolicy(dmarcTxt)
    result.dmarc.policy = parsed.policy
    result.dmarc.rua = parsed.rua
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

  return result
}
