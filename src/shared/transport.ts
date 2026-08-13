import type {
  MtaStsPolicy,
  TransportReason,
  TransportSecurityResult,
  TransportSecurityStatus
} from './types'

/** RFC 8460: `_smtp._tls.<domain>` TXT, `v=TLSRPTv1; rua=mailto:…,https://…`. */
export function parseTlsRptRecord(records: string[]): { found: boolean; rua: string[] } {
  const record = records.find((r) => /v\s*=\s*TLSRPTv1/i.test(r))
  if (!record) return { found: false, rua: [] }
  const rua = /(?:^|;)\s*rua\s*=\s*([^;]+)/i.exec(record)?.[1] ?? ''
  return {
    found: true,
    rua: rua
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
  }
}

/** RFC 8461: `_mta-sts.<domain>` TXT, `v=STSv1; id=20260813T120000`. */
export function parseMtaStsTxt(records: string[]): { found: boolean; id: string | null } {
  const record = records.find((r) => /v\s*=\s*STSv1/i.test(r))
  if (!record) return { found: false, id: null }
  return { found: true, id: /(?:^|;)\s*id\s*=\s*([^;\s]+)/i.exec(record)?.[1]?.trim() ?? null }
}

/** RFC 8461 policy file: `key: value` lines, `mx:` may repeat. */
export function parseMtaStsPolicy(text: string): MtaStsPolicy {
  const policy: MtaStsPolicy = { version: null, mode: null, mx: [], maxAgeSeconds: null }
  for (const line of text.split(/\r?\n/)) {
    const match = /^\s*([a-z_]+)\s*:\s*(.+?)\s*$/i.exec(line)
    if (!match) continue
    const key = match[1].toLowerCase()
    const value = match[2].trim()
    if (key === 'version') policy.version = value
    else if (key === 'mode') {
      const mode = value.toLowerCase()
      policy.mode = mode === 'enforce' || mode === 'testing' || mode === 'none' ? mode : null
    } else if (key === 'mx') policy.mx.push(value.toLowerCase().replace(/\.$/, ''))
    else if (key === 'max_age') {
      const n = Number(value)
      policy.maxAgeSeconds = Number.isFinite(n) ? Math.round(n) : null
    }
  }
  return policy
}

/** MTA-STS pattern match: a leading `*.` stands for exactly one label. */
export function mxMatchesPattern(host: string, pattern: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, '')
  const p = pattern.toLowerCase().replace(/\.$/, '')
  if (!h || !p) return false
  if (!p.startsWith('*.')) return h === p
  const suffix = p.slice(2)
  if (!h.endsWith(`.${suffix}`)) return false
  const label = h.slice(0, h.length - suffix.length - 1)
  return label.length > 0 && !label.includes('.')
}

/** RFC 8461 recommends at least two weeks; below a week a rollback is barely a policy. */
export const MIN_MAX_AGE_SECONDS = 604_800

/**
 * Grade transport security from the collected records.
 * MTA-STS with an unreachable policy or uncovered MX is worse than no MTA-STS
 * at all: senders in enforce mode then refuse delivery.
 */
export function evaluateTransportSecurity(
  input: Omit<TransportSecurityResult, 'status' | 'reasons'>
): { status: TransportSecurityStatus; reasons: TransportReason[] } {
  const reasons: TransportReason[] = []
  let status: TransportSecurityStatus = 'ok'
  const worse = (next: TransportSecurityStatus): void => {
    const rank: Record<TransportSecurityStatus, number> = { ok: 0, warn: 1, bad: 2, unknown: 3 }
    if (rank[next] > rank[status] && status !== 'unknown') status = next
  }
  const note = (key: string, level: TransportReason['level'] = 'ok'): void => {
    reasons.push({ key, level })
    if (level !== 'ok') worse(level)
  }

  const { tlsrpt, mtaSts, dane } = input

  if (tlsrpt.found) note('transport.reason.tlsrptOk')
  else note('transport.reason.noTlsrpt', 'warn')
  if (tlsrpt.found && tlsrpt.rua.length === 0) note('transport.reason.tlsrptNoRua', 'warn')

  if (!mtaSts.found) {
    note('transport.reason.noMtaSts', 'warn')
  } else if (!mtaSts.policy) {
    note('transport.reason.policyMissing', 'bad')
  } else {
    const mode = mtaSts.policy.mode
    if (mode === 'enforce') note('transport.reason.mtaStsEnforce')
    else if (mode === 'testing') note('transport.reason.mtaStsTesting', 'warn')
    else note('transport.reason.mtaStsNone', 'warn')
    const maxAge = mtaSts.policy.maxAgeSeconds
    if (maxAge != null && maxAge < MIN_MAX_AGE_SECONDS) note('transport.reason.shortMaxAge', 'warn')
    const hosts = dane.mx.map((m) => m.host)
    const uncovered = hosts.filter(
      (host) => !mtaSts.policy!.mx.some((pattern) => mxMatchesPattern(host, pattern))
    )
    if (hosts.length > 0 && uncovered.length > 0) {
      note('transport.reason.mxNotCovered', mode === 'enforce' ? 'bad' : 'warn')
    }
  }

  if (dane.mx.length === 0) note('transport.reason.noMx', 'warn')
  else if (dane.mx.every((m) => m.found)) note('transport.reason.daneAll')
  else if (dane.mx.some((m) => m.found)) note('transport.reason.danePartial', 'warn')
  else note('transport.reason.noDane')

  const order: Record<TransportReason['level'], number> = { bad: 0, warn: 1, ok: 2 }
  reasons.sort((a, b) => order[a.level] - order[b.level])
  return { status, reasons }
}
