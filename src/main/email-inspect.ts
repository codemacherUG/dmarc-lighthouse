import { t } from '../shared/i18n'
import { decodeEmailBytes, EmailInspectError, inspectEmail } from '../shared/email-inspect'
import type {
  DkimSignatureInfo,
  EmailInspectResponse,
  EmailInspectResult,
  IpInfo
} from '../shared/types'
import { resolveTxtReliable } from './dns-env'
import { verifyDkimSignatureCryptographically } from './dkim-verify'
import { resolveIps } from './ipinfo'

function mapError(err: unknown): EmailInspectResponse {
  if (err instanceof EmailInspectError) {
    const key =
      err.key === 'unsupportedMsg'
        ? 'email.unsupportedMsg'
        : err.key === 'empty'
          ? 'email.emptyFile'
          : 'email.notEmail'
    return { ok: false, message: t(key) }
  }
  return { ok: false, message: err instanceof Error ? err.message : String(err) }
}

async function lookupDkimDnsRecord(domain: string, selector: string): Promise<string | null> {
  try {
    const txt = (await resolveTxtReliable(`${selector}._domainkey.${domain}`)).map((parts) =>
      parts.join('')
    )
    return txt.find((r) => /v\s*=\s*DKIM1/i.test(r) || /(?:^|;)\s*p\s*=/i.test(r)) ?? null
  } catch {
    return null
  }
}

async function verifyDkimSignatures(
  rawText: string,
  signatures: DkimSignatureInfo[]
): Promise<DkimSignatureInfo[]> {
  if (signatures.length === 0) return signatures
  return Promise.all(
    signatures.map(async (sig) => {
      if (!sig.domain || !sig.selector) {
        return { ...sig, cryptoStatus: 'unverified' as const }
      }
      const dnsRecord = await lookupDkimDnsRecord(sig.domain, sig.selector)
      const verified = verifyDkimSignatureCryptographically(rawText, sig, dnsRecord)
      return {
        ...sig,
        cryptoStatus: verified.status,
        cryptoDetail: verified.detail
      }
    })
  )
}

async function enrichAndVerifyEmail(
  rawText: string,
  result: EmailInspectResult
): Promise<EmailInspectResult> {
  const ips = [
    ...new Set(result.hops.map((h) => h.fromIp).filter((ip): ip is string => Boolean(ip)))
  ]
  const [infos, verifiedSigs] = await Promise.all([
    ips.length > 0 ? resolveIps(ips).catch((): IpInfo[] => []) : Promise.resolve<IpInfo[]>([]),
    verifyDkimSignatures(rawText, result.dkimSignatures)
  ])
  const byIp = new Map<string, IpInfo>(infos.map((info) => [info.ip, info] as const))
  return {
    ...result,
    dkimSignatures: verifiedSigs,
    hops: result.hops.map((hop) => ({
      ...hop,
      ipInfo: hop.fromIp ? (byIp.get(hop.fromIp) ?? null) : null
    }))
  }
}

export async function inspectEmailBuffer(
  data: Uint8Array,
  fileName: string
): Promise<EmailInspectResponse> {
  try {
    const text = decodeEmailBytes(data)
    const result = inspectEmail(text, fileName)
    return { ok: true, result: await enrichAndVerifyEmail(text, result) }
  } catch (err) {
    return mapError(err)
  }
}

export async function inspectEmailText(
  text: string,
  fileName = 'paste.eml'
): Promise<EmailInspectResponse> {
  try {
    const result = inspectEmail(text, fileName)
    return { ok: true, result: await enrichAndVerifyEmail(text, result) }
  } catch (err) {
    return mapError(err)
  }
}
