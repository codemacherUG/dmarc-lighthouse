import { createSocket } from 'node:dgram'
import { createConnection } from 'node:net'
import { promises as dns } from 'node:dns'
import { pickDnsServers, PUBLIC_DNS_FALLBACK } from './dns-env'

/**
 * Node's resolver has no TLSA support, so DANE needs a hand-built query.
 * Only what a TLSA lookup requires: one question, EDNS0 (with DO=1) for DNSSEC AD bit & larger answers,
 * plus RFC 1035 §4.2.2 TCP fallback when the UDP response has TC=1 (truncated).
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
  header.writeUInt16BE(0x0120, 2) // standard query, RD=1 + AD=1 (request authenticated data bit)
  header.writeUInt16BE(1, 4) // QDCOUNT
  header.writeUInt16BE(1, 10) // ARCOUNT: the OPT record below
  const question = Buffer.concat([encodeName(name), Buffer.alloc(4)])
  question.writeUInt16BE(type, question.length - 4)
  question.writeUInt16BE(1, question.length - 2) // class IN
  // OPT pseudo-record announcing a 4096-byte UDP buffer + DO=1 (0x8000 in Z flags).
  const opt = Buffer.from([0, 0, 41, 0x10, 0x00, 0, 0, 0x80, 0, 0, 0])
  return Buffer.concat([header, question, opt])
}

/** Advance past a (possibly compressed) name and return the next offset. */
function skipName(buf: Buffer, offset: number): number {
  let pos = offset
  let jumps = 0
  while (pos < buf.length && jumps < 64) {
    const len = buf[pos]
    if (len === 0) return pos + 1
    if ((len & 0xc0) === 0xc0) return pos + 2
    pos += len + 1
    jumps++
  }
  throw new Error('Malformed DNS name')
}

export interface TlsaRecord {
  usage: number
  selector: number
  matchingType: number
  data: string
}

export interface DecodedTlsaResponse {
  records: TlsaRecord[]
  dnssecValidated: boolean
  truncated: boolean
}

export function isTruncatedDnsResponse(buf: Buffer): boolean {
  if (buf.length < 4) return false
  return (buf.readUInt16BE(2) & 0x0200) !== 0
}

export function isAuthenticatedDnsResponse(buf: Buffer): boolean {
  if (buf.length < 4) return false
  return (buf.readUInt16BE(2) & 0x0020) !== 0
}

export function decodeTlsaResponse(buf: Buffer): DecodedTlsaResponse {
  if (buf.length < 12) throw new Error('Short DNS response')
  const flags = buf.readUInt16BE(2)
  const rcode = flags & 0x0f
  const truncated = (flags & 0x0200) !== 0
  const dnssecValidated = (flags & 0x0020) !== 0
  if (rcode === 3) return { records: [], dnssecValidated, truncated } // NXDOMAIN: simply no TLSA
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
    if (type === TYPE_TLSA && rdLength >= 4 && rdStart + rdLength <= buf.length) {
      out.push({
        usage: buf[rdStart],
        selector: buf[rdStart + 1],
        matchingType: buf[rdStart + 2],
        data: buf.subarray(rdStart + 3, rdStart + rdLength).toString('hex')
      })
    }
    pos = rdStart + rdLength
  }
  return { records: out, dnssecValidated, truncated }
}

export function decodeTlsaAnswers(buf: Buffer): TlsaRecord[] {
  return decodeTlsaResponse(buf).records
}

export function formatTlsa(record: TlsaRecord): string {
  const digest = record.data.length > 32 ? `${record.data.slice(0, 32)}…` : record.data
  return `${record.usage} ${record.selector} ${record.matchingType} ${digest}`
}

/** Frame a DNS query for TCP transport (2-byte big-endian length prefix per RFC 1035 §4.2.2). */
export function encodeTcpDnsFrame(query: Buffer): Buffer {
  const prefix = Buffer.alloc(2)
  prefix.writeUInt16BE(query.length, 0)
  return Buffer.concat([prefix, query])
}

async function queryDnsWireTcp(
  query: Buffer,
  id: number,
  server: string,
  timeoutMs: number
): Promise<Buffer> {
  return await new Promise<Buffer>((resolve, reject) => {
    const socket = createConnection({ host: server, port: 53 })
    const chunks: Buffer[] = []
    let expectedLength: number | null = null
    let settled = false

    const done = (err: Error | null, msg?: Buffer): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try {
        socket.destroy()
      } catch {
        // ignore
      }
      if (err) reject(err)
      else resolve(msg ?? Buffer.alloc(0))
    }

    const timer = setTimeout(() => done(new Error('TCP DNS query timed out')), timeoutMs)

    socket.on('connect', () => {
      socket.write(encodeTcpDnsFrame(query), (err) => {
        if (err) done(err)
      })
    })

    socket.on('data', (chunk: Buffer) => {
      chunks.push(chunk)
      const buf = Buffer.concat(chunks)
      if (expectedLength === null && buf.length >= 2) {
        expectedLength = buf.readUInt16BE(0)
      }
      if (expectedLength !== null && buf.length >= 2 + expectedLength) {
        const msg = buf.subarray(2, 2 + expectedLength)
        if (msg.length >= 2 && msg.readUInt16BE(0) !== id) {
          done(new Error('Mismatched TCP DNS transaction ID'))
          return
        }
        done(null, msg)
      }
    })

    socket.on('error', (err) => done(err))
    socket.on('close', () => {
      if (!settled) done(new Error('TCP DNS connection closed before full response'))
    })
  })
}

async function queryDnsWireUdp(
  query: Buffer,
  id: number,
  server: string,
  timeoutMs: number
): Promise<Buffer> {
  const ipv6 = server.includes(':')
  const socket = createSocket(ipv6 ? 'udp6' : 'udp4')
  return await new Promise<Buffer>((resolve, reject) => {
    let settled = false
    const done = (err: Error | null, msg?: Buffer): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try {
        socket.close()
      } catch {
        // already closed
      }
      if (err) reject(err)
      else resolve(msg ?? Buffer.alloc(0))
    }
    const timer = setTimeout(() => done(new Error('UDP DNS query timed out')), timeoutMs)
    socket.on('message', (msg) => {
      if (msg.length >= 2 && msg.readUInt16BE(0) !== id) return
      done(null, msg)
    })
    socket.on('error', (err) => done(err))
    socket.send(query, 53, server, (err) => {
      if (err) done(err)
    })
  })
}

export async function queryTlsaWithMeta(
  name: string,
  timeoutMs = 4000
): Promise<DecodedTlsaResponse> {
  const rawServer = pickDnsServers(dns.getServers())[0] ?? PUBLIC_DNS_FALLBACK[0]
  const server = rawServer.replace(/%.*$/, '')
  const id = Math.floor(Math.random() * 0xffff)
  const query = encodeQuery(name, TYPE_TLSA, id)

  const udpMsg = await queryDnsWireUdp(query, id, server, timeoutMs)
  if (isTruncatedDnsResponse(udpMsg)) {
    const tcpMsg = await queryDnsWireTcp(query, id, server, timeoutMs)
    return decodeTlsaResponse(tcpMsg)
  }
  return decodeTlsaResponse(udpMsg)
}

/** One UDP query (with TCP fallback on TC=1) against a usable system resolver; resolves empty when nothing answers. */
export async function queryTlsa(name: string, timeoutMs = 4000): Promise<TlsaRecord[]> {
  return (await queryTlsaWithMeta(name, timeoutMs)).records
}
