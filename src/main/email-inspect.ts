import { t } from '../shared/i18n'
import { decodeEmailBytes, EmailInspectError, inspectEmail } from '../shared/email-inspect'
import type { EmailInspectResponse, EmailInspectResult } from '../shared/types'
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

async function enrichHops(result: EmailInspectResult): Promise<EmailInspectResult> {
  const ips = [
    ...new Set(result.hops.map((h) => h.fromIp).filter((ip): ip is string => Boolean(ip)))
  ]
  if (ips.length === 0) return result
  try {
    const infos = await resolveIps(ips)
    const byIp = new Map(infos.map((info) => [info.ip, info]))
    return {
      ...result,
      hops: result.hops.map((hop) => ({
        ...hop,
        ipInfo: hop.fromIp ? (byIp.get(hop.fromIp) ?? null) : null
      }))
    }
  } catch {
    return result
  }
}

export async function inspectEmailBuffer(
  data: Uint8Array,
  fileName: string
): Promise<EmailInspectResponse> {
  try {
    const text = decodeEmailBytes(data)
    const result = inspectEmail(text, fileName)
    return { ok: true, result: await enrichHops(result) }
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
    return { ok: true, result: await enrichHops(result) }
  } catch (err) {
    return mapError(err)
  }
}
