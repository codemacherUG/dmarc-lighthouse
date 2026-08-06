import { shell } from 'electron'

const ALLOWED_SCHEMES = new Set(['https:', 'mailto:'])

/**
 * Open a URL in the system handler. Rejects dangerous schemes (file:, javascript:, http:, …).
 */
export async function openExternalSafe(url: string): Promise<void> {
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    throw new Error(`Invalid URL: ${url}`)
  }
  if (!ALLOWED_SCHEMES.has(parsed.protocol)) {
    throw new Error(`Blocked URL scheme: ${parsed.protocol}`)
  }
  await shell.openExternal(parsed.toString())
}
