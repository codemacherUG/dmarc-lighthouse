/**
 * Flatten Error + nested `cause` (undici/Chromium often hide the real reason
 * behind a generic "fetch failed" / "net::ERR_*" wrapper).
 */
export function formatNetworkError(err: unknown): string {
  const parts: string[] = []
  const seen = new Set<unknown>()
  let cur: unknown = err

  while (cur != null && !seen.has(cur)) {
    seen.add(cur)
    if (cur instanceof Error) {
      const code =
        'code' in cur && cur.code != null && String(cur.code).trim()
          ? String(cur.code).trim()
          : ''
      const msg = cur.message?.trim() ?? ''
      if (msg && code && !msg.includes(code)) parts.push(`${msg} (${code})`)
      else if (msg) parts.push(msg)
      else if (code) parts.push(code)
      cur = cur.cause
      continue
    }
    if (typeof cur === 'string' && cur.trim()) {
      parts.push(cur.trim())
    }
    break
  }

  const unique: string[] = []
  for (const part of parts) {
    if (!unique.includes(part)) unique.push(part)
  }
  return unique.join(': ') || 'Unknown network error'
}
