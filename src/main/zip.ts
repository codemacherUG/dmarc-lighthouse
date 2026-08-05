import { deflateRawSync } from 'zlib'

/** CRC-32 (ISO 3309 / ZIP). */
export function crc32(buf: Buffer): number {
  let c = ~0
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i]!
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? (c >>> 1) ^ 0xedb88320 : c >>> 1
    }
  }
  return ~c >>> 0
}

function u16(n: number): Buffer {
  const b = Buffer.alloc(2)
  b.writeUInt16LE(n >>> 0, 0)
  return b
}

function u32(n: number): Buffer {
  const b = Buffer.alloc(4)
  b.writeUInt32LE(n >>> 0, 0)
  return b
}

/**
 * Build a minimal ZIP archive with one DEFLATE-compressed entry.
 * Good enough for a single DMARC XML attachment — no external zip dependency.
 */
export function zipSingleFile(filename: string, content: Buffer | string): Buffer {
  const name = Buffer.from(filename, 'utf8')
  const data = typeof content === 'string' ? Buffer.from(content, 'utf8') : content
  const compressed = deflateRawSync(data)
  const checksum = crc32(data)

  const localHeader = Buffer.concat([
    u32(0x04034b50), // local file header signature
    u16(20), // version needed
    u16(0), // flags
    u16(8), // compression: deflate
    u16(0), // mod time
    u16(0), // mod date
    u32(checksum),
    u32(compressed.length),
    u32(data.length),
    u16(name.length),
    u16(0), // extra length
    name
  ])

  const centralHeader = Buffer.concat([
    u32(0x02014b50), // central directory signature
    u16(20), // version made by
    u16(20), // version needed
    u16(0), // flags
    u16(8), // compression
    u16(0), // mod time
    u16(0), // mod date
    u32(checksum),
    u32(compressed.length),
    u32(data.length),
    u16(name.length),
    u16(0), // extra
    u16(0), // comment
    u16(0), // disk start
    u16(0), // internal attrs
    u32(0), // external attrs
    u32(0), // relative offset of local header
    name
  ])

  const end = Buffer.concat([
    u32(0x06054b50), // end of central directory
    u16(0), // disk number
    u16(0), // disk with CD
    u16(1), // entries on disk
    u16(1), // total entries
    u32(centralHeader.length),
    u32(localHeader.length + compressed.length),
    u16(0) // comment length
  ])

  return Buffer.concat([localHeader, compressed, centralHeader, end])
}
