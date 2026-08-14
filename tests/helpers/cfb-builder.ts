/** Minimal OLE Compound File writer for Outlook .msg tests. */

const SECTOR = 512
const MINI = 64
const CUTOFF = 4096
const END = 0xfffffffe
const FREE = 0xffffffff
const FATSECT = 0xfffffffd
const NOSTREAM = 0xffffffff

function writeU16(buf: Uint8Array, offset: number, value: number): void {
  buf[offset] = value & 0xff
  buf[offset + 1] = (value >>> 8) & 0xff
}

function writeU32(buf: Uint8Array, offset: number, value: number): void {
  buf[offset] = value & 0xff
  buf[offset + 1] = (value >>> 8) & 0xff
  buf[offset + 2] = (value >>> 16) & 0xff
  buf[offset + 3] = (value >>> 24) & 0xff
}

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

function range(start: number, count: number): number[] {
  return Array.from({ length: count }, (_, i) => start + i)
}

function chain(fat: number[], ids: number[]): void {
  if (ids.length === 0) return
  for (let i = 0; i < ids.length - 1; i++) fat[ids[i]!] = ids[i + 1]!
  fat[ids[ids.length - 1]!] = END
}

function encodeDirName(name: string): { raw: Uint8Array; byteLen: number } {
  const raw = new Uint8Array(64)
  const n = Math.min(name.length, 31)
  for (let i = 0; i < n; i++) writeU16(raw, i * 2, name.charCodeAt(i))
  return { raw, byteLen: (n + 1) * 2 }
}

function writeDirEntry(
  buf: Uint8Array,
  offset: number,
  entry: {
    name: string
    type: number
    color: number
    left: number
    right: number
    child: number
    start: number
    size: number
  }
): void {
  const { raw, byteLen } = encodeDirName(entry.name)
  buf.set(raw, offset)
  writeU16(buf, offset + 64, byteLen)
  buf[offset + 66] = entry.type
  buf[offset + 67] = entry.color
  writeU32(buf, offset + 68, entry.left)
  writeU32(buf, offset + 72, entry.right)
  writeU32(buf, offset + 76, entry.child)
  writeU32(buf, offset + 116, entry.start)
  writeU32(buf, offset + 120, entry.size >>> 0)
}

export function utf16leZ(text: string): Uint8Array {
  const out = new Uint8Array((text.length + 1) * 2)
  for (let i = 0; i < text.length; i++) writeU16(out, i * 2, text.charCodeAt(i))
  return out
}

/**
 * Build a CFB with named streams under the root (MSG-style `__substg1.0_…`).
 * Streams smaller than 4096 bytes go into the mini stream, like Outlook.
 */
export function buildCompoundFile(streams: Record<string, Uint8Array>): Uint8Array {
  const list = Object.entries(streams).map(([name, data]) => ({ name, data }))
  const miniItems = list.filter((s) => s.data.length < CUTOFF)
  const fatItems = list.filter((s) => s.data.length >= CUTOFF)

  const miniFat: number[] = []
  const miniChunks: Uint8Array[] = []
  const miniStart = new Map<string, number>()
  let miniSector = 0
  for (const item of miniItems) {
    if (item.data.length === 0) {
      miniStart.set(item.name, END)
      continue
    }
    miniStart.set(item.name, miniSector)
    const paddedLen = Math.ceil(item.data.length / MINI) * MINI
    const padded = new Uint8Array(paddedLen)
    padded.set(item.data)
    const count = paddedLen / MINI
    for (let i = 0; i < count; i++) {
      miniFat.push(i === count - 1 ? END : miniSector + 1)
      miniChunks.push(padded.subarray(i * MINI, (i + 1) * MINI))
      miniSector++
    }
  }
  const miniStreamData = concat(miniChunks)

  type Dir = {
    name: string
    type: number
    color: number
    left: number
    right: number
    child: number
    start: number
    size: number
  }
  const entries: Dir[] = [
    {
      name: 'Root Entry',
      type: 5,
      color: 1,
      left: NOSTREAM,
      right: NOSTREAM,
      child: list.length > 0 ? 1 : NOSTREAM,
      start: END,
      size: miniStreamData.length
    }
  ]
  for (let i = 0; i < list.length; i++) {
    const s = list[i]!
    entries.push({
      name: s.name,
      type: 2,
      color: 1,
      left: NOSTREAM,
      right: i + 1 < list.length ? i + 2 : NOSTREAM,
      child: NOSTREAM,
      start: END,
      size: s.data.length
    })
  }

  const dirSectors = Math.max(1, Math.ceil((entries.length * 128) / SECTOR))
  const miniFatSectors = miniFat.length === 0 ? 0 : Math.ceil((miniFat.length * 4) / SECTOR)
  const miniStreamSectors =
    miniStreamData.length === 0 ? 0 : Math.ceil(miniStreamData.length / SECTOR)
  const regularSectorsNeeded = fatItems.reduce((n, s) => n + Math.ceil(s.data.length / SECTOR), 0)

  let fatSectors = 1
  let totalSectors = 0
  for (let i = 0; i < 8; i++) {
    totalSectors =
      fatSectors + dirSectors + miniFatSectors + miniStreamSectors + regularSectorsNeeded
    const needed = Math.max(1, Math.ceil((totalSectors * 4) / SECTOR))
    if (needed === fatSectors) break
    fatSectors = needed
  }
  totalSectors = fatSectors + dirSectors + miniFatSectors + miniStreamSectors + regularSectorsNeeded

  let next = 0
  const fatSectorIds = range(next, fatSectors)
  next += fatSectors
  const dirSectorIds = range(next, dirSectors)
  next += dirSectors
  const miniFatSectorIds = range(next, miniFatSectors)
  next += miniFatSectors
  const miniStreamSectorIds = range(next, miniStreamSectors)
  next += miniStreamSectors

  const fatTable = new Array<number>(totalSectors).fill(FREE)
  for (const id of fatSectorIds) fatTable[id] = FATSECT
  chain(fatTable, dirSectorIds)
  chain(fatTable, miniFatSectorIds)
  chain(fatTable, miniStreamSectorIds)
  if (miniStreamSectorIds.length > 0) entries[0]!.start = miniStreamSectorIds[0]!

  const regularIds = new Map<string, number[]>()
  for (let i = 0; i < list.length; i++) {
    const s = list[i]!
    const ent = entries[i + 1]!
    if (s.data.length < CUTOFF) {
      ent.start = miniStart.get(s.name) ?? END
      continue
    }
    const count = Math.ceil(s.data.length / SECTOR)
    const ids = range(next, count)
    next += count
    chain(fatTable, ids)
    ent.start = ids[0]!
    regularIds.set(s.name, ids)
  }
  if (next !== totalSectors) {
    throw new Error(`CFB layout mismatch: next=${next} total=${totalSectors}`)
  }

  const sectors = Array.from({ length: totalSectors }, () => new Uint8Array(SECTOR))

  const fatBytes = new Uint8Array(fatSectors * SECTOR)
  for (let i = 0; i < fatBytes.length / 4; i++) writeU32(fatBytes, i * 4, FREE)
  for (let i = 0; i < fatTable.length; i++) writeU32(fatBytes, i * 4, fatTable[i]!)
  for (let i = 0; i < fatSectors; i++) {
    sectors[fatSectorIds[i]!] = fatBytes.subarray(i * SECTOR, (i + 1) * SECTOR)
  }

  const dirBuf = new Uint8Array(dirSectors * SECTOR)
  for (let i = 0; i < entries.length; i++) writeDirEntry(dirBuf, i * 128, entries[i]!)
  for (let i = 0; i < dirSectors; i++) {
    sectors[dirSectorIds[i]!] = dirBuf.subarray(i * SECTOR, (i + 1) * SECTOR)
  }

  if (miniFatSectors > 0) {
    const mf = new Uint8Array(miniFatSectors * SECTOR)
    for (let i = 0; i < mf.length / 4; i++) writeU32(mf, i * 4, FREE)
    for (let i = 0; i < miniFat.length; i++) writeU32(mf, i * 4, miniFat[i]!)
    for (let i = 0; i < miniFatSectors; i++) {
      sectors[miniFatSectorIds[i]!] = mf.subarray(i * SECTOR, (i + 1) * SECTOR)
    }
  }

  if (miniStreamSectors > 0) {
    const paddedMini = new Uint8Array(miniStreamSectors * SECTOR)
    paddedMini.set(miniStreamData)
    for (let i = 0; i < miniStreamSectors; i++) {
      sectors[miniStreamSectorIds[i]!] = paddedMini.subarray(i * SECTOR, (i + 1) * SECTOR)
    }
  }

  for (const s of fatItems) {
    const ids = regularIds.get(s.name)
    if (!ids) continue
    const padded = new Uint8Array(ids.length * SECTOR)
    padded.set(s.data)
    for (let i = 0; i < ids.length; i++) {
      sectors[ids[i]!] = padded.subarray(i * SECTOR, (i + 1) * SECTOR)
    }
  }

  const header = new Uint8Array(SECTOR)
  header.set([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])
  writeU16(header, 0x18, 0x003e)
  writeU16(header, 0x1a, 3)
  writeU16(header, 0x1c, 0xfffe)
  writeU16(header, 0x1e, 9)
  writeU16(header, 0x20, 6)
  writeU32(header, 0x2c, fatSectors)
  writeU32(header, 0x30, dirSectorIds[0]!)
  writeU32(header, 0x38, CUTOFF)
  writeU32(header, 0x3c, miniFatSectorIds[0] ?? END)
  writeU32(header, 0x40, miniFatSectors)
  writeU32(header, 0x44, END)
  writeU32(header, 0x48, 0)
  for (let i = 0; i < 109; i++) {
    writeU32(header, 0x4c + i * 4, i < fatSectors ? fatSectorIds[i]! : FREE)
  }

  return concat([header, ...sectors])
}
