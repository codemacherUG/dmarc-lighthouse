import { promises as dns } from 'node:dns'
import { t } from '../shared/i18n'
import {
  evaluateTransportSecurity,
  parseMtaStsPolicy,
  parseMtaStsTxt,
  parseTlsRptRecord
} from '../shared/transport'
import type {
  DaneMxCheck,
  MtaStsCheck,
  TlsRptCheck,
  TransportSecurityResult
} from '../shared/types'
import { formatTlsa, queryTlsa } from './dnswire'

const POLICY_TIMEOUT_MS = 8000
/** RFC 8461 caps the policy at 64 kB; anything larger is not a policy file. */
const POLICY_MAX_BYTES = 64 * 1024
const MAX_MX_HOSTS = 5

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

async function txtRecords(name: string): Promise<string[]> {
  return (await dns.resolveTxt(name)).map((parts) => parts.join(''))
}

async function checkTlsRpt(domain: string): Promise<TlsRptCheck> {
  try {
    const records = await txtRecords(`_smtp._tls.${domain}`)
    return { ...parseTlsRptRecord(records), records }
  } catch (err) {
    return { found: false, records: [], rua: [], error: errorText(err) }
  }
}

async function fetchMtaStsPolicy(domain: string): Promise<{ text: string | null; error?: string }> {
  const url = `https://mta-sts.${domain}/.well-known/mta-sts.txt`
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), POLICY_TIMEOUT_MS)
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      redirect: 'error',
      headers: { accept: 'text/plain' }
    })
    if (!response.ok) return { text: null, error: `HTTP ${response.status}` }
    const body = await response.text()
    if (body.length > POLICY_MAX_BYTES)
      return { text: null, error: t('main.transportPolicyTooBig') }
    return { text: body }
  } catch (err) {
    return { text: null, error: errorText(err) }
  } finally {
    clearTimeout(timer)
  }
}

async function checkMtaSts(domain: string): Promise<MtaStsCheck> {
  const policyUrl = `https://mta-sts.${domain}/.well-known/mta-sts.txt`
  let records: string[] = []
  try {
    records = await txtRecords(`_mta-sts.${domain}`)
  } catch (err) {
    return {
      found: false,
      id: null,
      records: [],
      policyUrl,
      policy: null,
      error: errorText(err)
    }
  }
  const txt = parseMtaStsTxt(records)
  if (!txt.found) {
    return { found: false, id: null, records, policyUrl, policy: null }
  }
  const fetched = await fetchMtaStsPolicy(domain)
  if (!fetched.text) {
    return { ...txt, records, policyUrl, policy: null, policyError: fetched.error }
  }
  const policy = parseMtaStsPolicy(fetched.text)
  return {
    ...txt,
    records,
    policyUrl,
    policy,
    // A policy without version or mode is not usable, so report it like a fetch error.
    ...(policy.mode ? {} : { policyError: t('main.transportPolicyInvalid') })
  }
}

async function checkDaneForMx(host: string, preference: number): Promise<DaneMxCheck> {
  try {
    const records = await queryTlsa(`_25._tcp.${host}`)
    return {
      host,
      preference,
      tlsa: records.map(formatTlsa),
      found: records.length > 0
    }
  } catch (err) {
    return { host, preference, tlsa: [], found: false, error: errorText(err) }
  }
}

/** TLS-RPT, MTA-STS and DANE for one domain, graded into a single status. */
export async function checkTransportSecurity(domainRaw: string): Promise<TransportSecurityResult> {
  const domain = domainRaw.trim().toLowerCase().replace(/\.$/, '')
  if (!domain || !/^[a-z0-9.-]+$/i.test(domain)) {
    throw new Error(t('main.invalidDomain'))
  }

  const [tlsrpt, mtaSts, mxResult] = await Promise.all([
    checkTlsRpt(domain),
    checkMtaSts(domain),
    dns.resolveMx(domain).then(
      (list) => ({ list, error: undefined as string | undefined }),
      (err) => ({ list: [], error: errorText(err) })
    )
  ])

  const hosts = mxResult.list
    .map((mx) => ({ host: mx.exchange.toLowerCase().replace(/\.$/, ''), preference: mx.priority }))
    .filter((mx) => Boolean(mx.host))
    .sort((a, b) => a.preference - b.preference)
    .slice(0, MAX_MX_HOSTS)

  const dane = {
    mx: await Promise.all(hosts.map((mx) => checkDaneForMx(mx.host, mx.preference))),
    ...(mxResult.error ? { error: mxResult.error } : {})
  }

  const base = { domain, tlsrpt, mtaSts, dane, checkedAt: new Date().toISOString() }
  return { ...base, ...evaluateTransportSecurity(base) }
}
