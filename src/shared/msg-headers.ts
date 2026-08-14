/**
 * Extract RFC 5322 headers from an Outlook .msg (OLE Compound File).
 * Only transport headers and a few identity properties are read — never the body.
 */

const OLE_MAGIC = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]
const MAXREGSECT = 0xfffffffa
const ENDOFCHAIN = 0xfffffffe
const NOSTREAM = 0xffffffff
const HEADER_SCAN = 256 * 1024

const TYPE_STREAM = 2
const TYPE_ROOT = 5

const PT_STRING8 = 0x001e
const PT_UNICODE = 0x001f
const PT_BINARY = 0x0102

/** PidTagTransportMessageHeaders — Internet headers as stored by Outlook. */
const PID_TRANSPORT_HEADERS = 0x007d
const PID_SUBJECT = 0x0037
const PID_NORMALIZED_SUBJECT = 0x0e1d
const PID_SENT_REPRESENTING_NAME = 0x0042
const PID_SENT_REPRESENTING_EMAIL = 0x0065
const PID_SENDER_NAME = 0x0c1a
const PID_SENDER_EMAIL = 0x0c1f
const PID_SENDER_SMTP = 0x5d01
const PID_SENT_REPRESENTING_SMTP = 0x5d02
const PID_DISPLAY_TO = 0x0e04
const PID_INTERNET_MESSAGE_ID = 0x1035

type DirEntry = {
  name: string
  type: number
  left: number
  right: number
  child: number
  start: number
  size: number
}

type Cfb = {
  bytes: Uint8Array
  sectorSize: number
  miniSize: number
  miniCutoff: number
  fat: number[]
  miniFat: number[]
  miniStream: Uint8Array
  entries: DirEntry[]
  root: DirEntry
}

function u16(view: DataView, offset: number): number {
  return view.getUint16(offset, true)
}

function u32(view: DataView, offset: number): number {
  return view.getUint32(offset, true)
}

export function isOleCompound(bytes: Uint8Array): boolean {
  if (bytes.length < OLE_MAGIC.length) return false
  return OLE_MAGIC.every((b, i) => bytes[i] === b)
}

function sectorOffset(sector: number, sectorSize: number): number {
  return (sector + 1) * sectorSize
}

function followChain(fat: number[], start: number, max: number): number[] | null {
  const out: number[] = []
  const seen = new Set<number>()
  let s = start
  while (s <= MAXREGSECT) {
    if (seen.has(s) || out.length >= max || s >= fat.length) return null
    seen.add(s)
    out.push(s)
    s = fat[s]!
  }
  return s === ENDOFCHAIN ? out : null
}

function readChainBytes(
  bytes: Uint8Array,
  fat: number[],
  start: number,
  sectorSize: number,
  maxSectors: number
): Uint8Array | null {
  const chain = followChain(fat, start, maxSectors)
  if (!chain || chain.length === 0) return null
  const out = new Uint8Array(chain.length * sectorSize)
  for (let i = 0; i < chain.length; i++) {
    const pos = sectorOffset(chain[i]!, sectorSize)
    if (pos < 0 || pos + sectorSize > bytes.length) return null
    out.set(bytes.subarray(pos, pos + sectorSize), i * sectorSize)
  }
  return out
}

function readSectors(
  bytes: Uint8Array,
  fat: number[],
  start: number,
  size: number,
  sectorSize: number
): Uint8Array | null {
  if (size === 0) return new Uint8Array(0)
  if (size < 0 || size > bytes.length) return null
  const raw = readChainBytes(bytes, fat, start, sectorSize, Math.ceil(size / sectorSize) + 2)
  if (!raw || (size > 0 && raw.length < size)) return null
  return raw.subarray(0, size)
}

function parseDirectory(raw: Uint8Array): DirEntry[] {
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength)
  const entries: DirEntry[] = []
  for (let off = 0; off + 128 <= raw.length; off += 128) {
    const type = raw[off + 66] ?? 0
    if (type === 0) {
      entries.push({
        name: '',
        type: 0,
        left: NOSTREAM,
        right: NOSTREAM,
        child: NOSTREAM,
        start: 0,
        size: 0
      })
      continue
    }
    const nameBytes = u16(view, off + 64)
    const charCount = Math.max(0, Math.min(32, Math.floor(nameBytes / 2)) - 1)
    let name = ''
    for (let i = 0; i < charCount; i++) {
      name += String.fromCharCode(u16(view, off + i * 2))
    }
    entries.push({
      name,
      type,
      left: u32(view, off + 68),
      right: u32(view, off + 72),
      child: u32(view, off + 76),
      start: u32(view, off + 116),
      size: u32(view, off + 120)
    })
  }
  return entries
}

function parseCfb(bytes: Uint8Array): Cfb | null {
  if (!isOleCompound(bytes) || bytes.length < 512) return null
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  if (u16(view, 0x1c) !== 0xfffe) return null
  const sectorShift = u16(view, 0x1e)
  const miniShift = u16(view, 0x20)
  if (sectorShift < 9 || sectorShift > 12) return null
  if (miniShift === 0 || miniShift >= sectorShift) return null
  const sectorSize = 1 << sectorShift
  const miniSize = 1 << miniShift
  const fatCount = u32(view, 0x2c)
  const firstDir = u32(view, 0x30)
  const miniCutoff = u32(view, 0x38)
  const firstMiniFat = u32(view, 0x3c)
  const miniFatCount = u32(view, 0x40)
  const firstDifat = u32(view, 0x44)
  const difatCount = u32(view, 0x48)
  if (fatCount === 0 || fatCount > 1_000_000) return null

  const fatSectors: number[] = []
  for (let i = 0; i < 109; i++) {
    const sec = u32(view, 0x4c + i * 4)
    if (sec <= MAXREGSECT) fatSectors.push(sec)
  }
  let difatSec = firstDifat
  const perDifat = sectorSize / 4 - 1
  const seenDifat = new Set<number>()
  for (let n = 0; n < difatCount && difatSec <= MAXREGSECT; n++) {
    if (seenDifat.has(difatSec)) return null
    seenDifat.add(difatSec)
    const pos = sectorOffset(difatSec, sectorSize)
    if (pos + sectorSize > bytes.length) return null
    for (let i = 0; i < perDifat; i++) {
      const sec = u32(view, pos + i * 4)
      if (sec <= MAXREGSECT) fatSectors.push(sec)
    }
    difatSec = u32(view, pos + perDifat * 4)
  }
  if (fatSectors.length < fatCount) return null

  const fat: number[] = []
  const entriesPerFat = sectorSize / 4
  for (let i = 0; i < fatCount; i++) {
    const sec = fatSectors[i]
    if (sec === undefined) return null
    const pos = sectorOffset(sec, sectorSize)
    if (pos + sectorSize > bytes.length) return null
    for (let j = 0; j < entriesPerFat; j++) fat.push(u32(view, pos + j * 4))
  }

  const dirRaw = readChainBytes(bytes, fat, firstDir, sectorSize, 256)
  if (!dirRaw) return null
  const entries = parseDirectory(dirRaw)
  const root = entries.find((e) => e.type === TYPE_ROOT)
  if (!root) return null

  const miniFat: number[] = []
  if (miniFatCount > 0 && firstMiniFat <= MAXREGSECT) {
    const miniFatBytes = readSectors(
      bytes,
      fat,
      firstMiniFat,
      miniFatCount * sectorSize,
      sectorSize
    )
    if (!miniFatBytes) return null
    const mv = new DataView(miniFatBytes.buffer, miniFatBytes.byteOffset, miniFatBytes.byteLength)
    for (let i = 0; i + 4 <= miniFatBytes.length; i += 4) miniFat.push(u32(mv, i))
  }

  const miniStream =
    root.size > 0
      ? (readSectors(bytes, fat, root.start, root.size, sectorSize) ?? new Uint8Array(0))
      : new Uint8Array(0)

  return {
    bytes,
    sectorSize,
    miniSize,
    miniCutoff,
    fat,
    miniFat,
    miniStream,
    entries,
    root
  }
}

function readStream(cfb: Cfb, entry: DirEntry): Uint8Array | null {
  const size = Math.min(entry.size, HEADER_SCAN)
  if (size === 0) return new Uint8Array(0)
  const useMini = entry.type !== TYPE_ROOT && cfb.miniCutoff > 0 && entry.size < cfb.miniCutoff
  if (!useMini) {
    return readSectors(cfb.bytes, cfb.fat, entry.start, size, cfb.sectorSize)
  }
  const max = Math.ceil(size / cfb.miniSize) + 2
  const chain = followChain(cfb.miniFat, entry.start, max)
  if (!chain) return null
  const out = new Uint8Array(size)
  let offset = 0
  for (const mini of chain) {
    if (offset >= size) break
    const pos = mini * cfb.miniSize
    const n = Math.min(cfb.miniSize, size - offset)
    if (pos < 0 || pos + n > cfb.miniStream.length) return null
    out.set(cfb.miniStream.subarray(pos, pos + n), offset)
    offset += n
  }
  return out
}

function rootStreams(cfb: Cfb): Map<string, DirEntry> {
  const map = new Map<string, DirEntry>()
  const stack = [cfb.root.child]
  const seen = new Set<number>()
  while (stack.length > 0) {
    const id = stack.pop()!
    if (id === NOSTREAM || seen.has(id) || id < 0 || id >= cfb.entries.length) continue
    seen.add(id)
    const entry = cfb.entries[id]
    if (!entry || entry.type === 0) continue
    stack.push(entry.left, entry.right)
    if (entry.type === TYPE_STREAM) map.set(entry.name, entry)
  }
  return map
}

function stripZ(text: string): string {
  return text.replace(/\0+$/g, '').replace(/^\uFEFF/, '')
}

function decodeAnsi(bytes: Uint8Array): string {
  try {
    return stripZ(new TextDecoder('windows-1252').decode(bytes))
  } catch {
    return stripZ(new TextDecoder('latin1').decode(bytes))
  }
}

function decodeString(bytes: Uint8Array, type: number): string {
  if (type === PT_UNICODE) {
    const even = bytes.length & ~1
    return stripZ(new TextDecoder('utf-16le').decode(bytes.subarray(0, even)))
  }
  if (type === PT_STRING8 || type === PT_BINARY) {
    if (type === PT_BINARY && bytes.length >= 2 && bytes[1] === 0) {
      const even = bytes.length & ~1
      const asUtf16 = stripZ(new TextDecoder('utf-16le').decode(bytes.subarray(0, even)))
      if (asUtf16.includes(':')) return asUtf16
    }
    return decodeAnsi(bytes)
  }
  return decodeAnsi(bytes)
}

function readTagged(cfb: Cfb, streams: Map<string, DirEntry>, tag: number): string | null {
  const hex = tag.toString(16).toUpperCase().padStart(4, '0')
  const prefer = [`${hex}${PT_UNICODE.toString(16).toUpperCase().padStart(4, '0')}`]
  prefer.push(`${hex}${PT_STRING8.toString(16).toUpperCase().padStart(4, '0')}`)
  prefer.push(`${hex}${PT_BINARY.toString(16).toUpperCase().padStart(4, '0')}`)
  for (const suffix of prefer) {
    const name = `__substg1.0_${suffix}`
    const entry =
      streams.get(name) ??
      [...streams.entries()].find(([n]) => n.toLowerCase() === name.toLowerCase())?.[1]
    if (!entry) continue
    const raw = readStream(cfb, entry)
    if (!raw || raw.length === 0) continue
    const type = Number.parseInt(suffix.slice(4), 16)
    const text = decodeString(raw, type).trim()
    if (text) return text
  }
  return null
}

function smtpAddress(value: string | null): string | null {
  if (!value) return null
  const trimmed = value.trim()
  if (/^SMTP:/i.test(trimmed)) return trimmed.slice(5).trim() || null
  if (trimmed.includes('@') && !trimmed.startsWith('/')) return trimmed
  return null
}

function formatMailbox(name: string | null, email: string | null): string | null {
  const addr = smtpAddress(email)
  const display = name?.trim() || null
  if (addr && display) {
    const quoted = /[",]/.test(display) ? `"${display.replace(/"/g, '\\"')}"` : display
    return `${quoted} <${addr}>`
  }
  return addr || display
}

function reconstructHeaders(cfb: Cfb, streams: Map<string, DirEntry>): string {
  const lines: string[] = []
  const from = formatMailbox(
    readTagged(cfb, streams, PID_SENT_REPRESENTING_NAME) ??
      readTagged(cfb, streams, PID_SENDER_NAME),
    readTagged(cfb, streams, PID_SENT_REPRESENTING_SMTP) ??
      readTagged(cfb, streams, PID_SENDER_SMTP) ??
      readTagged(cfb, streams, PID_SENT_REPRESENTING_EMAIL) ??
      readTagged(cfb, streams, PID_SENDER_EMAIL)
  )
  if (from) lines.push(`From: ${from}`)
  const to = readTagged(cfb, streams, PID_DISPLAY_TO)
  if (to) lines.push(`To: ${to}`)
  const subject =
    readTagged(cfb, streams, PID_SUBJECT) ?? readTagged(cfb, streams, PID_NORMALIZED_SUBJECT)
  if (subject) lines.push(`Subject: ${subject}`)
  const messageId = readTagged(cfb, streams, PID_INTERNET_MESSAGE_ID)
  if (messageId) {
    lines.push(`Message-ID: ${messageId.includes('<') ? messageId : `<${messageId}>`}`)
  }
  if (lines.length === 0) return ''
  lines.push('MIME-Version: 1.0')
  return `${lines.join('\r\n')}\r\n\r\n`
}

/**
 * Return RFC 5322 header text from a .msg buffer, or null if it is not a readable MSG.
 * Prefers PidTagTransportMessageHeaders (Received / Auth-Results / DKIM).
 */
export function extractMsgRfc822(bytes: Uint8Array): string | null {
  const cfb = parseCfb(bytes)
  if (!cfb) return null
  const streams = rootStreams(cfb)
  if (streams.size === 0) return null
  const transport = readTagged(cfb, streams, PID_TRANSPORT_HEADERS)
  if (transport) return transport.endsWith('\n') ? transport : `${transport}\n`
  return reconstructHeaders(cfb, streams) || null
}
