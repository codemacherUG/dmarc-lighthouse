import { isRelaxedAligned, organizationalDomain } from './domain'
import type {
  ArcSetInfo,
  AuthMethodResult,
  AuthResultsBlock,
  DkimSignatureInfo,
  EmailHop,
  EmailIdentity,
  EmailInspectCheck,
  EmailInspectResult,
  EmailInspectStatus
} from './types'

export type EmailInspectErrorKey = 'unsupportedMsg' | 'notEmail' | 'empty'

export class EmailInspectError extends Error {
  constructor(readonly key: EmailInspectErrorKey) {
    super(key)
    this.name = 'EmailInspectError'
  }
}

const HEADER_SCAN = 256 * 1024
const OLE_MAGIC = [0xd0, 0xcf, 0x11, 0xe0]

const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g
const BRACKET_IP_RE = /\[(?:IPv6:)?([0-9a-f:.]+)\]/gi
const TLS_VERSION_RE = /(?:using\s+|version\s*=\s*)(TLS[v_]?[\d._]+)/i
const TLS_CIPHER_RE = /(?:with\s+cipher|cipher\s*=)\s*([A-Za-z0-9_:-]+)/i

const AUTH_RESULT_OK = new Set(['pass', 'ok', 'valid'])
const AUTH_RESULT_BAD = new Set(['fail', 'hardfail', 'invalid', 'permerror'])

function isOleCompound(bytes: Uint8Array): boolean {
  if (bytes.length < 4) return false
  return OLE_MAGIC.every((b, i) => bytes[i] === b)
}

/** Decode a file/buffer into RFC 5322 text (headers + start of body). */
export function decodeEmailBytes(bytes: Uint8Array): string {
  if (isOleCompound(bytes)) throw new EmailInspectError('unsupportedMsg')
  let offset = 0
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    offset = 3
  }
  const end = Math.min(bytes.length, offset + HEADER_SCAN)
  let text = new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(offset, end))
  const firstNl = text.indexOf('\n')
  if (firstNl > 0 && firstNl < 24 && /^\d+\s*$/.test(text.slice(0, firstNl))) {
    text = text.slice(firstNl + 1)
  }
  return text.replace(/^\uFEFF/, '')
}

function decodeQBytes(encoded: string): Uint8Array {
  const normalized = encoded.replace(/_/g, ' ')
  const bytes: number[] = []
  for (let i = 0; i < normalized.length; i++) {
    if (normalized[i] === '=' && i + 2 < normalized.length) {
      const hex = normalized.slice(i + 1, i + 3)
      if (/^[0-9a-fA-F]{2}$/.test(hex)) {
        bytes.push(Number.parseInt(hex, 16))
        i += 2
        continue
      }
    }
    bytes.push(normalized.charCodeAt(i) & 0xff)
  }
  return Uint8Array.from(bytes)
}

function decodeBase64Bytes(encoded: string): Uint8Array {
  const clean = encoded.replace(/\s+/g, '')
  const bin = atob(clean)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

function decodeCharset(charset: string, bytes: Uint8Array): string {
  const label = charset.trim().toLowerCase() || 'utf-8'
  try {
    return new TextDecoder(label).decode(bytes)
  } catch {
    try {
      return new TextDecoder('utf-8').decode(bytes)
    } catch {
      return Array.from(bytes, (b) => String.fromCharCode(b)).join('')
    }
  }
}

function decodeOneWord(charset: string, encoding: string, text: string): string {
  const bytes = encoding.toLowerCase() === 'b' ? decodeBase64Bytes(text) : decodeQBytes(text)
  return decodeCharset(charset, bytes)
}

/** RFC 2047 encoded-words; whitespace between adjacent words is dropped. */
export function decodeEncodedWords(value: string): string {
  return value.replace(
    /((?:=\?[^?]+\?[bBqQ]\?[^?]*\?=)(?:\s+(?:=\?[^?]+\?[bBqQ]\?[^?]*\?=))*)/g,
    (block) =>
      block
        .replace(/\s+/g, '')
        .replace(/=\?([^?]+)\?([bBqQ])\?([^?]*)\?=/g, (_m, charset, enc, text) =>
          decodeOneWord(charset, enc, text)
        )
  )
}

export function parseHeaderMap(raw: string): Map<string, string[]> {
  const unfolded = raw.replace(/\r\n[ \t]+/g, ' ').replace(/\n[ \t]+/g, ' ')
  const splitAt = unfolded.search(/\r?\n\r?\n/)
  const headerText = splitAt >= 0 ? unfolded.slice(0, splitAt) : unfolded
  const map = new Map<string, string[]>()
  for (const line of headerText.split(/\r?\n/)) {
    const idx = line.indexOf(':')
    if (idx <= 0) continue
    const key = line.slice(0, idx).trim().toLowerCase()
    const value = line.slice(idx + 1).trim()
    if (!key) continue
    const list = map.get(key)
    if (list) list.push(value)
    else map.set(key, [value])
  }
  return map
}

function firstHeader(map: Map<string, string[]>, name: string): string | null {
  const values = map.get(name.toLowerCase())
  return values?.[0] ?? null
}

function headerValues(map: Map<string, string[]>, name: string): string[] {
  return map.get(name.toLowerCase()) ?? []
}

export function parseMailbox(value: string | null): {
  address: string | null
  display: string | null
  domain: string | null
} {
  if (!value) return { address: null, display: null, domain: null }
  const decoded = decodeEncodedWords(value).replace(/\s+/g, ' ').trim()
  const angleAt = decoded.lastIndexOf('<')
  const angleEnd = decoded.lastIndexOf('>')
  const hasAngle = angleAt >= 0 && angleEnd > angleAt
  const address = (hasAngle ? decoded.slice(angleAt + 1, angleEnd) : decoded)
    .trim()
    .replace(/^mailto:/i, '')
  const display = hasAngle ? decoded.slice(0, angleAt).replace(/^"|"$/g, '').trim() : null
  const at = address.lastIndexOf('@')
  const domain = at > 0 ? organizationalDomain(address.slice(at + 1)) : null
  const cleanAddr = address.includes('@') ? address : null
  return { address: cleanAddr, display: display || null, domain }
}

function parseTagList(raw: string): Record<string, string> {
  const tags: Record<string, string> = {}
  for (const part of raw.split(';')) {
    const eq = part.indexOf('=')
    if (eq <= 0) continue
    const key = part.slice(0, eq).trim().toLowerCase()
    const value = part
      .slice(eq + 1)
      .trim()
      .replace(/^"|"$/g, '')
    if (key) tags[key] = value
  }
  return tags
}

export function normalizeTlsVersion(raw: string | null): string | null {
  if (!raw) return null
  const match = /tls[v_]?[\s_]*(\d)(?:[._](\d))?/i.exec(raw)
  if (!match) return raw.replace(/\s+/g, ' ').trim()
  return `TLS ${match[1]}.${match[2] ?? '0'}`
}

function extractFromIp(raw: string): string | null {
  BRACKET_IP_RE.lastIndex = 0
  const bracket = BRACKET_IP_RE.exec(raw)
  if (bracket?.[1]) {
    const inner = bracket[1]
    if (inner.includes(':') || IPV4_RE.test(inner)) return inner.replace(/^IPv6:/i, '')
  }
  IPV4_RE.lastIndex = 0
  const v4 = raw.match(IPV4_RE)
  return v4?.[0] ?? null
}

function tokenAfter(raw: string, keyword: string): string | null {
  const skip = keyword === 'with' ? '(?!cipher\\b)' : ''
  const match = new RegExp(`\\b${keyword}\\s+${skip}(\\S+)`, 'i').exec(raw)
  if (!match) return null
  return match[1].replace(/[;>,]+$/, '').replace(/^<|>$/g, '') || null
}

export function parseReceivedHop(raw: string): Omit<EmailHop, 'index'> {
  const fromHost = tokenAfter(raw, 'from')
  const byHost = tokenAfter(raw, 'by')
  const protocol = tokenAfter(raw, 'with')
  const id = tokenAfter(raw, 'id')
  const forAddr = tokenAfter(raw, 'for')
  const tlsRaw = TLS_VERSION_RE.exec(raw)?.[1] ?? null
  const tlsVersion = normalizeTlsVersion(tlsRaw)
  const tlsCipher = TLS_CIPHER_RE.exec(raw)?.[1] ?? null
  const proto = protocol ?? ''
  const withTls = Boolean(tlsVersion) || /ESMTPS|SMTPS|HTTPS/i.test(proto)
  const datePart = raw.includes(';') ? raw.slice(raw.lastIndexOf(';') + 1).trim() : null
  let timestamp: string | null = datePart
  if (datePart) {
    const parsed = Date.parse(datePart.replace(/\s+\([^)]+\)\s*$/, ''))
    if (!Number.isNaN(parsed)) timestamp = new Date(parsed).toISOString()
  }
  return {
    fromHost: fromHost?.replace(/[;>,]+$/, '') ?? null,
    fromIp: extractFromIp(raw),
    byHost: byHost?.replace(/[;>,]+$/, '') ?? null,
    protocol: protocol ?? null,
    tlsVersion,
    tlsCipher,
    withTls,
    timestamp,
    forAddr: forAddr ?? null,
    id: id ?? null,
    raw
  }
}

function splitAuthClauses(rest: string): string[] {
  const clauses: string[] = []
  let depth = 0
  let current = ''
  for (const ch of rest) {
    if (ch === '(') depth += 1
    else if (ch === ')' && depth > 0) depth -= 1
    if (ch === ';' && depth === 0) {
      const trimmed = current.trim()
      if (trimmed) clauses.push(trimmed)
      current = ''
      continue
    }
    current += ch
  }
  const trimmed = current.trim()
  if (trimmed) clauses.push(trimmed)
  return clauses
}

function parseAuthClause(clause: string): AuthMethodResult | null {
  const match = /^([a-z0-9-]+)\s*=\s*([a-z0-9-]+)/i.exec(clause.trim())
  if (!match) return null
  const reason = /\(([^)]*)\)/.exec(clause)?.[1]?.trim() ?? null
  const properties: Record<string, string> = {}
  const propRe = /([a-z0-9-]+)\.([a-z0-9-]+)\s*=\s*("([^"]*)"|[^\s;]+)/gi
  let prop: RegExpExecArray | null
  while ((prop = propRe.exec(clause))) {
    properties[`${prop[1].toLowerCase()}.${prop[2].toLowerCase()}`] = (prop[4] ?? prop[3]).replace(
      /[;>,]+$/,
      ''
    )
  }
  const action = /\baction\s*=\s*([a-z0-9-]+)/i.exec(clause)?.[1]
  if (action) properties['action'] = action.toLowerCase()
  return {
    method: match[1].toLowerCase(),
    result: match[2].toLowerCase(),
    reason,
    properties
  }
}

export function parseAuthResults(raw: string): AuthResultsBlock {
  let text = raw.trim()
  text = text.replace(/^i\s*=\s*\d+\s*;\s*/i, '')
  const semi = text.indexOf(';')
  let authservId = ''
  let rest = text
  if (semi >= 0) {
    const intro = text.slice(0, semi).trim()
    if (intro.includes('=')) {
      rest = text
    } else {
      authservId = intro.split(/\s+/)[0] ?? ''
      rest = text.slice(semi + 1)
    }
  }
  const methods = splitAuthClauses(rest)
    .map(parseAuthClause)
    .filter((m): m is AuthMethodResult => Boolean(m))
  const leftover = rest.trim()
  const skipped = methods.length === 0 && /^(none)?$/i.test(leftover)
  return { authservId, methods, raw, skipped }
}

export function parseDkimSignature(raw: string): DkimSignatureInfo {
  const tags = parseTagList(raw)
  return {
    domain: tags.d?.replace(/\.$/, '') ?? null,
    selector: tags.s ?? null,
    identity: tags.i ?? null,
    algorithm: tags.a ?? null,
    raw
  }
}

function parseReceivedSpf(raw: string): { result: string; raw: string } {
  const result = /^([a-z]+)/i.exec(raw.trim())?.[1]?.toLowerCase() ?? 'none'
  return { result, raw }
}

function collectArc(headers: Map<string, string[]>): ArcSetInfo[] {
  const byInstance = new Map<number, ArcSetInfo>()
  for (const seal of headerValues(headers, 'arc-seal')) {
    const tags = parseTagList(seal)
    const instance = Number(tags.i) || 0
    byInstance.set(instance, {
      instance,
      cv: tags.cv?.toLowerCase() ?? null,
      authservId: tags.d ?? null
    })
  }
  for (const aar of headerValues(headers, 'arc-authentication-results')) {
    const instance = Number(/^i\s*=\s*(\d+)/i.exec(aar)?.[1] ?? 0)
    const parsed = parseAuthResults(aar)
    const existing = byInstance.get(instance)
    if (existing) {
      if (!existing.authservId && parsed.authservId) existing.authservId = parsed.authservId
    } else {
      byInstance.set(instance, {
        instance,
        cv: null,
        authservId: parsed.authservId || null
      })
    }
  }
  return [...byInstance.values()].sort((a, b) => a.instance - b.instance)
}

function domainFromProp(value: string | null | undefined): string | null {
  if (!value) return null
  const trimmed = value.trim().replace(/^<|>$/g, '')
  if (trimmed.includes('@')) return organizationalDomain(trimmed)
  return organizationalDomain(trimmed.replace(/^@/, ''))
}

function isPrivateIp(ip: string | null | undefined): boolean {
  if (!ip) return false
  const v = ip.toLowerCase().replace(/^\[|\]$/g, '')
  if (v === '::1') return true
  if (v.includes(':')) {
    const first = v.split(':')[0] ?? ''
    return first.startsWith('fd') || first.startsWith('fc') || first.startsWith('fe8')
  }
  const parts = v.split('.').map(Number)
  if (parts.length !== 4 || parts.some((n) => !Number.isFinite(n))) return false
  const [a, b] = parts
  if (a === 10 || a === 127) return true
  if (a === 192 && b === 168) return true
  if (a === 169 && b === 254) return true
  return a === 172 && b >= 16 && b <= 31
}

function isLocalHop(hop: EmailHop): boolean {
  if (/^LMTP$/i.test(hop.protocol ?? '')) return true
  if (isPrivateIp(hop.fromIp)) return true
  const hosts = `${hop.fromHost ?? ''} ${hop.byHost ?? ''}`
  return /\blocalhost\b/i.test(hosts)
}

function pickMethods(blocks: AuthResultsBlock[], method: string): AuthMethodResult[] {
  return blocks.flatMap((b) => b.methods.filter((m) => m.method === method))
}

function worse(current: EmailInspectStatus, next: EmailInspectStatus): EmailInspectStatus {
  const rank: Record<EmailInspectStatus, number> = { ok: 0, unknown: 1, warn: 2, bad: 3 }
  return rank[next] > rank[current] ? next : current
}

function check(
  id: string,
  status: EmailInspectStatus,
  titleKey: string,
  detailKey: string,
  params?: Record<string, string | number>
): EmailInspectCheck {
  return { id, status, titleKey, detailKey, params }
}

function evaluate(input: {
  identity: EmailIdentity
  hops: EmailHop[]
  authResults: AuthResultsBlock[]
  receivedSpf: Array<{ result: string; raw: string }>
  dkimSignatures: DkimSignatureInfo[]
  arc: ArcSetInfo[]
  contentType: string | null
  spamStatus: string | null
}): { checks: EmailInspectCheck[]; status: EmailInspectStatus; verdictKey: string } {
  const checks: EmailInspectCheck[] = []
  const fromDomain = input.identity.fromDomain
  const spfMethods = pickMethods(input.authResults, 'spf')
  const dkimMethods = pickMethods(input.authResults, 'dkim')
  const dmarcMethods = pickMethods(input.authResults, 'dmarc')
  const bimiMethods = pickMethods(input.authResults, 'bimi')
  const arcPass = input.arc.some((a) => a.cv === 'pass')
  const arcFail = input.arc.some((a) => a.cv === 'fail')

  const authSkipped =
    input.authResults.some((b) => b.skipped) &&
    spfMethods.length === 0 &&
    dkimMethods.length === 0 &&
    dmarcMethods.length === 0
  const alignedSignature = input.dkimSignatures.find((s) =>
    isRelaxedAligned(s.domain, fromDomain)
  )

  const spfAr = spfMethods[0]
  const spfResult = spfAr?.result ?? input.receivedSpf[0]?.result ?? null
  const spfMailfrom =
    domainFromProp(spfAr?.properties['smtp.mailfrom']) ?? input.identity.returnPathDomain
  if (!spfResult) {
    checks.push(
      check(
        'spf',
        'unknown',
        'email.check.spf',
        authSkipped ? 'email.detail.spf.skipped' : 'email.detail.spf.missing'
      )
    )
  } else if (AUTH_RESULT_OK.has(spfResult) && isRelaxedAligned(spfMailfrom, fromDomain)) {
    checks.push(
      check('spf', 'ok', 'email.check.spf', 'email.detail.spf.pass', {
        domain: spfMailfrom ?? '—'
      })
    )
  } else if (AUTH_RESULT_OK.has(spfResult)) {
    checks.push(
      check('spf', 'warn', 'email.check.spf', 'email.detail.spf.passUnaligned', {
        domain: spfMailfrom ?? '—'
      })
    )
  } else if (spfResult === 'softfail') {
    checks.push(check('spf', 'warn', 'email.check.spf', 'email.detail.spf.softfail'))
  } else if (spfResult === 'none') {
    checks.push(check('spf', 'warn', 'email.check.spf', 'email.detail.spf.none'))
  } else if (AUTH_RESULT_BAD.has(spfResult) && arcPass) {
    checks.push(check('spf', 'warn', 'email.check.spf', 'email.detail.spf.forwarded'))
  } else {
    checks.push(
      check('spf', 'bad', 'email.check.spf', 'email.detail.spf.fail', { result: spfResult })
    )
  }

  const alignedDkimPass = dkimMethods.find((m) => {
    if (!AUTH_RESULT_OK.has(m.result)) return false
    const d = domainFromProp(m.properties['header.d'] ?? m.properties['header.i'])
    return isRelaxedAligned(d, fromDomain)
  })
  const anyDkimPass = dkimMethods.find((m) => AUTH_RESULT_OK.has(m.result))
  const anyDkimFail = dkimMethods.find((m) => AUTH_RESULT_BAD.has(m.result))
  if (alignedDkimPass) {
    const d =
      domainFromProp(
        alignedDkimPass.properties['header.d'] ?? alignedDkimPass.properties['header.i']
      ) ?? '—'
    checks.push(check('dkim', 'ok', 'email.check.dkim', 'email.detail.dkim.pass', { domain: d }))
  } else if (anyDkimPass) {
    const d =
      domainFromProp(anyDkimPass.properties['header.d'] ?? anyDkimPass.properties['header.i']) ??
      '—'
    checks.push(
      check('dkim', 'warn', 'email.check.dkim', 'email.detail.dkim.passUnaligned', { domain: d })
    )
  } else if (anyDkimFail) {
    checks.push(check('dkim', 'bad', 'email.check.dkim', 'email.detail.dkim.fail'))
  } else if (input.dkimSignatures.length > 0 && dkimMethods.length === 0) {
    if (alignedSignature) {
      checks.push(
        check('dkim', 'unknown', 'email.check.dkim', 'email.detail.dkim.unverifiedAligned', {
          domain: alignedSignature.domain ?? '—'
        })
      )
    } else {
      checks.push(check('dkim', 'unknown', 'email.check.dkim', 'email.detail.dkim.missingAr'))
    }
  } else if (input.dkimSignatures.length === 0) {
    checks.push(check('dkim', 'warn', 'email.check.dkim', 'email.detail.dkim.unsigned'))
  } else {
    checks.push(check('dkim', 'warn', 'email.check.dkim', 'email.detail.dkim.none'))
  }

  const dmarc = dmarcMethods[0]
  if (!dmarc) {
    checks.push(
      check(
        'dmarc',
        'unknown',
        'email.check.dmarc',
        authSkipped ? 'email.detail.dmarc.skipped' : 'email.detail.dmarc.missing'
      )
    )
  } else if (AUTH_RESULT_OK.has(dmarc.result)) {
    checks.push(check('dmarc', 'ok', 'email.check.dmarc', 'email.detail.dmarc.pass'))
  } else if (dmarc.result === 'none') {
    checks.push(check('dmarc', 'warn', 'email.check.dmarc', 'email.detail.dmarc.none'))
  } else {
    checks.push(
      check('dmarc', 'bad', 'email.check.dmarc', 'email.detail.dmarc.fail', {
        result: dmarc.result
      })
    )
  }

  const spfAligned = Boolean(
    spfResult && AUTH_RESULT_OK.has(spfResult) && isRelaxedAligned(spfMailfrom, fromDomain)
  )
  const dkimAligned = Boolean(alignedDkimPass)
  if (spfAligned && dkimAligned) {
    checks.push(check('alignment', 'ok', 'email.check.alignment', 'email.detail.alignment.ok'))
  } else if (dkimAligned) {
    checks.push(
      check('alignment', 'warn', 'email.check.alignment', 'email.detail.alignment.dkimOnly')
    )
  } else if (spfAligned) {
    checks.push(
      check('alignment', 'warn', 'email.check.alignment', 'email.detail.alignment.spfOnly')
    )
  } else if (!spfResult && dkimMethods.length === 0) {
    if (alignedSignature) {
      checks.push(
        check('alignment', 'unknown', 'email.check.alignment', 'email.detail.alignment.unverified')
      )
    } else {
      checks.push(
        check('alignment', 'unknown', 'email.check.alignment', 'email.detail.alignment.unknown')
      )
    }
  } else {
    checks.push(check('alignment', 'bad', 'email.check.alignment', 'email.detail.alignment.none'))
  }

  if (input.hops.length === 0) {
    checks.push(check('tls', 'unknown', 'email.check.tls', 'email.detail.tls.unknown'))
  } else if (input.hops.every(isLocalHop)) {
    checks.push(check('tls', 'unknown', 'email.check.tls', 'email.detail.tls.local'))
  } else {
    const internetHops = input.hops.filter((h) => !isLocalHop(h))
    const graded = internetHops.length > 0 ? internetHops : input.hops
    const tlsHops = graded.filter((h) => h.withTls)
    const oldTls = graded.some((h) => {
      const v = h.tlsVersion ?? ''
      return v === 'TLS 1.0' || v === 'TLS 1.1'
    })
    if (oldTls) {
      checks.push(check('tls', 'warn', 'email.check.tls', 'email.detail.tls.old'))
    } else if (tlsHops.length === graded.length) {
      checks.push(
        check('tls', 'ok', 'email.check.tls', 'email.detail.tls.ok', { count: graded.length })
      )
    } else if (tlsHops.length === 0) {
      checks.push(check('tls', 'warn', 'email.check.tls', 'email.detail.tls.none'))
    } else {
      checks.push(
        check('tls', 'warn', 'email.check.tls', 'email.detail.tls.partial', {
          tls: tlsHops.length,
          total: graded.length
        })
      )
    }
  }

  if (arcFail) {
    checks.push(check('arc', 'bad', 'email.check.arc', 'email.detail.arc.fail'))
  } else if (arcPass) {
    checks.push(
      check('arc', 'ok', 'email.check.arc', 'email.detail.arc.pass', { count: input.arc.length })
    )
  }

  const bimi = bimiMethods[0]
  if (bimi) {
    if (AUTH_RESULT_OK.has(bimi.result)) {
      checks.push(check('bimi', 'ok', 'email.check.bimi', 'email.detail.bimi.pass'))
    } else if (bimi.result !== 'none') {
      checks.push(check('bimi', 'warn', 'email.check.bimi', 'email.detail.bimi.fail'))
    }
  }

  if (input.identity.replyToDomain && fromDomain && input.identity.replyToDomain !== fromDomain) {
    checks.push(
      check('replyTo', 'warn', 'email.check.replyTo', 'email.detail.replyTo.diff', {
        from: fromDomain,
        reply: input.identity.replyToDomain
      })
    )
  }

  const display = input.identity.fromDisplay ?? ''
  const displayAddr = display.match(/[\w.+-]+@([\w.-]+\.[a-z]{2,})/i)
  if (displayAddr?.[1] && fromDomain && organizationalDomain(displayAddr[1]) !== fromDomain) {
    checks.push(
      check('displayName', 'warn', 'email.check.displayName', 'email.detail.displayName.spoof', {
        display,
        from: fromDomain
      })
    )
  }

  const ct = (input.contentType ?? '').toLowerCase()
  if (
    ct.includes('pkcs7-mime') ||
    ct.includes('pkcs7-signature') ||
    ct.includes('application/pkcs7')
  ) {
    checks.push(
      check('encryption', 'ok', 'email.check.encryption', 'email.detail.encryption.smime')
    )
  } else if (
    ct.includes('pgp') ||
    ct.includes('multipart/encrypted') ||
    ct.includes('application/pgp')
  ) {
    checks.push(check('encryption', 'ok', 'email.check.encryption', 'email.detail.encryption.pgp'))
  }

  if (authSkipped) {
    checks.push(
      check('authResults', 'unknown', 'email.check.authResults', 'email.detail.authResults.skipped')
    )
  } else if (input.authResults.length === 0 && input.receivedSpf.length === 0) {
    checks.push(
      check('authResults', 'unknown', 'email.check.authResults', 'email.detail.authResults.missing')
    )
  }

  const spam = (input.spamStatus ?? '').toLowerCase()
  if (/^yes\b/.test(spam) || /\b(?:yes|true)\b/.test(spam.split(',')[0] ?? '')) {
    checks.push(check('spam', 'warn', 'email.check.spam', 'email.detail.spam.yes'))
  }

  let status: EmailInspectStatus = 'ok'
  for (const c of checks) status = worse(status, c.status)
  const dmarcStatus = checks.find((c) => c.id === 'dmarc')?.status
  const verdictKey =
    dmarcStatus === 'ok' && status === 'warn'
      ? 'email.verdict.warn'
      : status === 'ok'
        ? 'email.verdict.ok'
        : status === 'bad'
          ? 'email.verdict.bad'
          : status === 'warn'
            ? 'email.verdict.warn'
            : 'email.verdict.unknown'
  return { checks, status, verdictKey }
}

export function looksLikeEmailMessage(text: string): boolean {
  const head = text.slice(0, 16_384)
  if (!/^From:/im.test(head) && !/^Return-Path:/im.test(head)) return false
  return (
    /^Received:/im.test(head) ||
    /^Authentication-Results:/im.test(head) ||
    /^DKIM-Signature:/im.test(head) ||
    /^MIME-Version:/im.test(head)
  )
}

/**
 * Parse RFC 5322 source and grade SPF, DKIM, DMARC, TLS hops, ARC and related signals.
 * Only headers are interpreted; the body is ignored.
 */
export function inspectEmail(source: string, fileName = 'message.eml'): EmailInspectResult {
  const trimmed = source.trim()
  if (!trimmed) throw new EmailInspectError('empty')
  if (!looksLikeEmailMessage(trimmed)) throw new EmailInspectError('notEmail')

  const headers = parseHeaderMap(trimmed)
  const from = parseMailbox(firstHeader(headers, 'from'))
  const returnPath = parseMailbox(firstHeader(headers, 'return-path'))
  const replyTo = parseMailbox(firstHeader(headers, 'reply-to'))
  const to = parseMailbox(firstHeader(headers, 'to'))
  const identity: EmailIdentity = {
    from: from.address,
    fromDisplay: from.display,
    fromDomain: from.domain,
    returnPath: returnPath.address,
    returnPathDomain: returnPath.domain,
    replyTo: replyTo.address,
    replyToDomain: replyTo.domain,
    to: to.address,
    subject: decodeEncodedWords(firstHeader(headers, 'subject') ?? '') || null,
    date: firstHeader(headers, 'date'),
    messageId: firstHeader(headers, 'message-id')
  }

  const received = headerValues(headers, 'received')
  const hops: EmailHop[] = received
    .map((raw) => parseReceivedHop(raw))
    .reverse()
    .map((hop, index) => {
      const row: EmailHop = { ...hop, index: index + 1 }
      row.local = isLocalHop(row)
      return row
    })

  const authResults = headerValues(headers, 'authentication-results').map(parseAuthResults)
  const receivedSpf = headerValues(headers, 'received-spf').map(parseReceivedSpf)
  const dkimSignatures = [
    ...headerValues(headers, 'dkim-signature'),
    ...headerValues(headers, 'x-google-dkim-signature')
  ].map(parseDkimSignature)
  const arc = collectArc(headers)
  const { checks, status, verdictKey } = evaluate({
    identity,
    hops,
    authResults,
    receivedSpf,
    dkimSignatures,
    arc,
    contentType: firstHeader(headers, 'content-type'),
    spamStatus: firstHeader(headers, 'x-spam-status')
  })

  return {
    fileName,
    identity,
    hops,
    authResults,
    receivedSpf,
    dkimSignatures,
    arc,
    checks,
    status,
    verdictKey
  }
}
