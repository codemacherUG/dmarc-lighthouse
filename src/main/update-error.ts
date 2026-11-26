/**
 * electron-updater packs the whole stack trace and the raw GitHub releases feed
 * (", XML: <?xml …") into `Error.message`. Reduce that to something a user can read
 * and tell transient connectivity problems apart from real update failures.
 */

const NET_CODE_RE = /\b(?:net::)?(ERR_[A-Z0-9_]+)\b/
const NODE_CODE_RE =
  /\b(ENOTFOUND|EAI_AGAIN|ECONNRESET|ECONNREFUSED|ECONNABORTED|ETIMEDOUT|ENETUNREACH|ENETDOWN|EHOSTUNREACH|EPIPE)\b/

/** Chromium net errors that mean "no usable connection right now", not "the release is broken". */
const TRANSIENT_NET_CODES = new Set([
  'ERR_NETWORK_CHANGED',
  'ERR_INTERNET_DISCONNECTED',
  'ERR_NAME_NOT_RESOLVED',
  'ERR_NAME_RESOLUTION_FAILED',
  'ERR_DNS_TIMED_OUT',
  'ERR_CONNECTION_RESET',
  'ERR_CONNECTION_REFUSED',
  'ERR_CONNECTION_CLOSED',
  'ERR_CONNECTION_ABORTED',
  'ERR_CONNECTION_FAILED',
  'ERR_CONNECTION_TIMED_OUT',
  'ERR_TIMED_OUT',
  'ERR_ADDRESS_UNREACHABLE',
  'ERR_NETWORK_IO_SUSPENDED',
  'ERR_PROXY_CONNECTION_FAILED',
  'ERR_TUNNEL_CONNECTION_FAILED',
  'ERR_EMPTY_RESPONSE',
  'ERR_SOCKET_NOT_CONNECTED'
])

const MAX_DETAIL_LENGTH = 200

export interface UpdateErrorInfo {
  /** Connectivity problem that is worth retrying and not worth a red banner. */
  transient: boolean
  /** Network error code (e.g. `ERR_NETWORK_CHANGED`, `ENOTFOUND`) when one was found. */
  code: string | null
  /** Single-line message without stack trace or feed dump. */
  detail: string
}

export function describeUpdateError(err: unknown): UpdateErrorInfo {
  const raw = err instanceof Error ? err.message || String(err) : String(err ?? '')

  // Only look for codes in the error text itself, not in the appended feed body.
  const xmlAt = raw.search(/,?\s*XML:\s*</)
  const text = xmlAt >= 0 ? raw.slice(0, xmlAt) : raw

  const netCode = NET_CODE_RE.exec(text)?.[1] ?? null
  const nodeCode = NODE_CODE_RE.exec(text)?.[1] ?? null
  const code = netCode ?? nodeCode
  const transient = netCode ? TRANSIENT_NET_CODES.has(netCode) : nodeCode != null

  // Cut the stack trace (" at fn (file:line:col)") and collapse whitespace.
  const stackAt = text.search(/\s+at\s+\S.*?(?:\(|:\d+:\d+)/)
  let detail = (stackAt >= 0 ? text.slice(0, stackAt) : text).replace(/\s+/g, ' ').trim()
  if (detail.length > MAX_DETAIL_LENGTH)
    detail = `${detail.slice(0, MAX_DETAIL_LENGTH - 1).trimEnd()}…`

  return { transient, code, detail: detail || 'Unknown error' }
}
