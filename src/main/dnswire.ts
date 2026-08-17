import { createSocket } from 'node:dgram'
import { promises as dns } from 'node:dns'
import { pickDnsServers, PUBLIC_DNS_FALLBACK } from './dns-env'

/**
 * Node's resolver has no TLSA support, so DANE needs a hand-built query.
 * Only what a TLSA lookup requires: one question, EDNS0 for larger answers.
 */
export const TYPE_TLSA = 52

export function encodeName(name: string): Buffer {
  const parts = name.replace(/\.$/, '').split('.').filter(Boolean)
  const chunks: Buffer[] = []
  for (const part of parts) {
    const label = Buffer.from(part, 'ascii')
    if (label.length > 63) throw new Error(`DNS label too long: ${part}`)
    chunks.push(Buffer.from([label.length]), label)
  }
  chunks.push(Buffer.from([0]))
  return Buffer.concat(chunks)
}

export function encodeQuery(name: string, type: number, id: number): Buffer {
  const header = Buffer.alloc(12)
  header.writeUInt16BE(id & 0xffff, 0)
  header.writeUInt16BE(0x0100, 2) // standard query, recursion desired
  header.writeUInt16BE(1, 4) // QDCOUNT
  header.writeUInt16BE(1, 10) // ARCOUNT: the OPT record below
  const question = Buffer.concat([encodeName(name), Buffer.alloc(4)])
  question.writeUInt16BE(type, question.length - 4)
  question.writeUInt16BE(1, question.length - 2) // class IN
  // OPT pseudo-record announcing a 4096-byte UDP buffer.
  const opt = Buffer.from([0, 0, 41, 0x10, 0x00, 0, 0, 0, 0, 0, 0])
  return Buffer.concat([header, question, opt])
}

/** Advance past a (possibly compressed) name and return the next offset. */
function skipName(buf: Buffer, offset: number): number {
  let pos = offset
  while (pos < buf.length) {
    const len = buf[pos]
    if (len === 0) return pos + 1
    if ((len & 0xc0) === 0xc0) return pos + 2
    pos += len + 1
  }
  throw new Error('Malformed DNS name')
}

export interface TlsaRecord {
  usage: number
  selector: number
  matchingType: number
  data: string
}

export function decodeTlsaAnswers(buf: Buffer): TlsaRecord[] {
  if (buf.length < 12) throw new Error('Short DNS response')
  const rcode = buf[3] & 0x0f
  if (rcode === 3) return [] // NXDOMAIN: simply no TLSA
  if (rcode !== 0) throw new Error(`DNS rcode ${rcode}`)
  const questions = buf.readUInt16BE(4)
  const answers = buf.readUInt16BE(6)
  let pos = 12
  for (let i = 0; i < questions; i++) {
    pos = skipName(buf, pos) + 4
  }
  const out: TlsaRecord[] = []
  for (let i = 0; i < answers && pos + 10 <= buf.length; i++) {
    pos = skipName(buf, pos)
    const type = buf.readUInt16BE(pos)
    const rdLength = buf.readUInt16BE(pos + 8)
    const rdStart = pos + 10
    if (type === TYPE_TLSA && rdLength >= 4) {
      out.push({
        usage: buf[rdStart],
        selector: buf[rdStart + 1],
        matchingType: buf[rdStart + 2],
        data: buf.subarray(rdStart + 3, rdStart + rdLength).toString('hex')
      })
    }
    pos = rdStart + rdLength
  }
  return out
}

export function formatTlsa(record: TlsaRecord): string {
  const digest = record.data.length > 32 ? `${record.data.slice(0, 32)}…` : record.data
  return `${record.usage} ${record.selector} ${record.matchingType} ${digest}`
}

/** One UDP query against a usable system resolver; resolves empty when nothing answers. */
export async function queryTlsa(name: string, timeoutMs = 4000): Promise<TlsaRecord[]> {
  const server =
    pickDnsServers(dns.getServers())[0] ?? PUBLIC_DNS_FALLBACK[0]
  const ipv6 = server.includes(':')
  const socket = createSocket(ipv6 ? 'udp6' : 'udp4')
  const id = Math.floor(Math.random() * 0xffff)
  const query = encodeQuery(name, TYPE_TLSA, id)

  return await new Promise<TlsaRecord[]>((resolve, reject) => {
    const done = (err: Error | null, records: TlsaRecord[] = []): void => {
      clearTimeout(timer)
      try {
        socket.close()
      } catch {
        // already closed
      }
      if (err) reject(err)
      else resolve(records)
    }
    const timer = setTimeout(() => done(new Error(`TLSA query timed out for ${name}`)), timeoutMs)
    socket.on('message', (msg) => {
      if (msg.length >= 2 && msg.readUInt16BE(0) !== id) return
      try {
        done(null, decodeTlsaAnswers(msg))
      } catch (err) {
        done(err instanceof Error ? err : new Error(String(err)))
      }
    })
    socket.on('error', (err) => done(err))
    socket.send(query, 53, server.replace(/%.*$/, ''), (err) => {
      if (err) done(err)
    })
  })
}
