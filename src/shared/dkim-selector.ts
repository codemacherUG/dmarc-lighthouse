import type { DomainDkimSelector } from './types'

export function normalizeDkimSelector(raw: string): string | null {
  let selector = raw.trim().toLowerCase().replace(/\.+$/, '')
  if (!selector) return null
  const marker = '._domainkey'
  const markerIndex = selector.indexOf(marker)
  if (markerIndex >= 0) selector = selector.slice(0, markerIndex)
  if (!selector || !/^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/.test(selector)) return null
  return selector
}

export function selectorsForDnsCheck(
  manual: string[],
  configured: DomainDkimSelector[],
  discovered: string[]
): string[] {
  if (manual.length > 0) return manual
  if (configured.length > 0) {
    return configured.filter(({ enabled }) => enabled).map(({ selector }) => selector)
  }
  return discovered
}
