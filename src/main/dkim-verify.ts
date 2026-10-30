import { createHash, createPublicKey, verify } from 'crypto'
import type { DkimCryptoStatus, DkimSignatureInfo } from '../shared/types'

function parseTagMap(raw: string): Map<string, string> {
  const map = new Map<string, string>()
  for (const part of raw.split(';')) {
    const eq = part.indexOf('=')
    if (eq <= 0) continue
    const key = part.slice(0, eq).trim().toLowerCase()
    const value = part.slice(eq + 1).trim()
    if (key) map.set(key, value)
  }
  return map
}

function splitRawHeadersAndBody(rawEmail: string): {
  headerLines: Array<{ name: string; rawLine: string }>
  body: string
} {
  const normalized = rawEmail.replace(/\r?\n/g, '\r\n')
  const sep = normalized.indexOf('\r\n\r\n')
  const headerPart = sep >= 0 ? normalized.slice(0, sep) : normalized
  const body = sep >= 0 ? normalized.slice(sep + 4) : ''

  const physicalLines = headerPart.split('\r\n')
  const unfoldedLines: string[] = []
  for (const line of physicalLines) {
    if (/^[ \t]/.test(line) && unfoldedLines.length > 0) {
      unfoldedLines[unfoldedLines.length - 1] += `\r\n${line}`
    } else if (line.includes(':')) {
      unfoldedLines.push(line)
    }
  }

  const headerLines = unfoldedLines.map((rawLine) => {
    const colon = rawLine.indexOf(':')
    const name = colon > 0 ? rawLine.slice(0, colon).trim() : ''
    return { name, rawLine }
  })

  return { headerLines, body }
}

/** RFC 6376 §3.4.3 / §3.4.4 body canonicalization. */
export function canonicalizeDkimBody(body: string, mode: 'simple' | 'relaxed'): string {
  const crlf = body.replace(/\r?\n/g, '\r\n')
  let lines = crlf.split('\r\n')
  // If body ended with \r\n, split leaves an empty trailing element
  if (crlf.endsWith('\r\n')) {
    lines.pop()
  }

  if (mode === 'relaxed') {
    lines = lines.map((line) => line.replace(/[ \t]+/g, ' ').replace(/ $/g, ''))
  }

  while (lines.length > 0 && lines[lines.length - 1] === '') {
    lines.pop()
  }

  if (lines.length === 0) {
    return mode === 'simple' ? '\r\n' : ''
  }
  return `${lines.join('\r\n')}\r\n`
}

/** RFC 6376 §3.4.1 / §3.4.2 header line canonicalization. */
export function canonicalizeDkimHeaderLine(rawLine: string, mode: 'simple' | 'relaxed'): string {
  if (mode === 'simple') return rawLine
  const unfolded = rawLine.replace(/\r?\n([ \t]+)/g, '$1')
  const colon = unfolded.indexOf(':')
  if (colon <= 0) return unfolded
  const name = unfolded.slice(0, colon).trim().toLowerCase()
  const value = unfolded
    .slice(colon + 1)
    .replace(/[ \t]+/g, ' ')
    .trim()
  return `${name}:${value}`
}

function stripDkimBTagValue(rawDkimHeaderLine: string): string {
  return rawDkimHeaderLine.replace(/(;\s*b\s*=\s*)([^;]*)/i, '$1')
}

function publicKeyFromDkimDnsRecord(record: string): ReturnType<typeof createPublicKey> | null {
  const tags = parseTagMap(record)
  const k = (tags.get('k') || 'rsa').toLowerCase()
  const p = (tags.get('p') || '').replace(/\s+/g, '')
  if (!p) return null
  try {
    if (k === 'ed25519') {
      const rawKey = Buffer.from(p, 'base64')
      if (rawKey.length !== 32) return null
      // RFC 8410 Ed25519 SPKI prefix (12 bytes) + 32-byte raw key
      const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex')
      return createPublicKey({
        key: Buffer.concat([spkiPrefix, rawKey]),
        format: 'der',
        type: 'spki'
      })
    }
    return createPublicKey({
      key: Buffer.from(p, 'base64'),
      format: 'der',
      type: 'spki'
    })
  } catch {
    return null
  }
}

/**
 * Cryptographically verify a single `DKIM-Signature` header against the raw RFC 5322 email
 * and the corresponding `_domainkey` TXT record.
 */
export function verifyDkimSignatureCryptographically(
  rawEmail: string,
  sig: DkimSignatureInfo,
  dnsTxtRecord: string | null
): { status: DkimCryptoStatus; detail: string | null } {
  const tags = parseTagMap(sig.raw.replace(/\r?\n[ \t]+/g, ' '))
  const algo = (tags.get('a') || sig.algorithm || 'rsa-sha256').toLowerCase()
  const bhExpected = (tags.get('bh') || '').replace(/\s+/g, '')
  const bSignature = (tags.get('b') || '').replace(/\s+/g, '')
  const hFields = (tags.get('h') || '')
    .split(':')
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean)
  const canonParts = (tags.get('c') || 'simple/simple').toLowerCase().split('/')
  const headerCanon: 'simple' | 'relaxed' = canonParts[0] === 'relaxed' ? 'relaxed' : 'simple'
  const bodyCanon: 'simple' | 'relaxed' = canonParts[1] === 'relaxed' ? 'relaxed' : 'simple'

  if (!bhExpected || !bSignature || hFields.length === 0) {
    return { status: 'unverified', detail: 'Incomplete DKIM-Signature tags' }
  }

  const hashAlg = algo.includes('sha1') ? 'sha1' : 'sha256'
  const { headerLines, body } = splitRawHeadersAndBody(rawEmail)
  let canonBody = canonicalizeDkimBody(body, bodyCanon)
  const lTag = tags.get('l')
  if (lTag && /^\d+$/.test(lTag)) {
    const limit = Number(lTag)
    const buf = Buffer.from(canonBody, 'utf8')
    if (limit < buf.length) {
      canonBody = buf.subarray(0, limit).toString('utf8')
    }
  }

  const bhActual = createHash(hashAlg).update(canonBody, 'utf8').digest('base64')
  if (bhActual !== bhExpected) {
    return { status: 'bodyMismatch', detail: `bh mismatch` }
  }

  if (!dnsTxtRecord) {
    return { status: 'keyMissing', detail: 'DKIM DNS key not found' }
  }
  const pubKey = publicKeyFromDkimDnsRecord(dnsTxtRecord)
  if (!pubKey) {
    return { status: 'keyMissing', detail: 'DKIM DNS key invalid or revoked' }
  }

  // RFC 6376 §5.4.2: consume matching headers bottom-up
  const consumed = new Set<number>()
  const signedHeaderLines: string[] = []
  for (const fieldName of hFields) {
    for (let i = headerLines.length - 1; i >= 0; i--) {
      if (consumed.has(i)) continue
      if (headerLines[i].name.toLowerCase() === fieldName) {
        consumed.add(i)
        signedHeaderLines.push(
          `${canonicalizeDkimHeaderLine(headerLines[i].rawLine, headerCanon)}\r\n`
        )
        break
      }
    }
  }

  // Find the matching DKIM-Signature header line itself (without trailing \r\n)
  const dkimHeaderEntry = headerLines.find(
    (h) =>
      /^(?:x-google-)?dkim-signature$/i.test(h.name) &&
      h.rawLine.replace(/\s+/g, '').includes(bSignature.slice(0, 16))
  ) ?? {
    name: 'DKIM-Signature',
    rawLine: `DKIM-Signature: ${sig.raw}`
  }

  const strippedDkimLine = canonicalizeDkimHeaderLine(
    stripDkimBTagValue(dkimHeaderEntry.rawLine),
    headerCanon
  )
  const signingInput = Buffer.from(`${signedHeaderLines.join('')}${strippedDkimLine}`, 'utf8')
  const sigBytes = Buffer.from(bSignature, 'base64')

  try {
    const ok = algo.startsWith('ed25519')
      ? verify(null, signingInput, pubKey, sigBytes)
      : verify(hashAlg, signingInput, pubKey, sigBytes)
    return ok
      ? { status: 'verified', detail: algo }
      : { status: 'signatureInvalid', detail: 'Cryptographic signature mismatch' }
  } catch (err) {
    return {
      status: 'signatureInvalid',
      detail: err instanceof Error ? err.message : String(err)
    }
  }
}
