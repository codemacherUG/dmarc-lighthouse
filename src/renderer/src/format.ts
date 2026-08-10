import { isAuthorizedSender, parseAuthorizedSenderPrefixes } from '../../shared/ipcidr'
import { getLocale, t } from '../../shared/i18n'
import type { IpInfo } from '../../shared/types'
import { state } from './state'

function isOwnSender(ip: string): boolean {
  const id = state.settings?.activeAccountId
  const account = state.settings?.accounts.find((a) => a.id === id)
  const prefixes = parseAuthorizedSenderPrefixes(account?.authorizedSenders ?? [])
  return isAuthorizedSender(ip, prefixes)
}

function isSpfSender(ip: string): boolean {
  return isAuthorizedSender(ip, state.spfPrefixes)
}

export function formatDate(iso: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleDateString(getLocale() === 'de' ? 'de-DE' : 'en-US')
}

export function formatRange(begin: string | null, end: string | null): string {
  return `${formatDate(begin)} – ${formatDate(end)}`
}

export function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
}

/** Known ESP/cloud label, else ASN org (ISP / network). */
export function resolveProviderLabel(
  info?: IpInfo | null,
  fallbackProvider?: string | null
): string | null {
  return fallbackProvider || info?.provider || info?.cloudProvider || info?.asOrg || null
}

export function formatIpMetaHtml(
  ip: string,
  fallbackProvider?: string | null,
  fallbackPtr?: string | null
): string {
  const meta = state.ipLabelCache.get(ip)
  const provider = resolveProviderLabel(meta, fallbackProvider)
  const ptr = fallbackPtr ?? meta?.ptr
  const bits: string[] = []
  // Role markers first (same badge row as geo/ASN/…).
  const own = isOwnSender(ip)
  const inSpf = isSpfSender(ip)
  const spfKnown = state.spfPrefixes.length > 0
  if (own && spfKnown && !inSpf) {
    bits.push(`<span class="badge own">${escapeHtml(t('ipMark.own'))}</span>`)
    bits.push(`<span class="badge not-in-spf">${escapeHtml(t('ipMark.notInSpf'))}</span>`)
  } else {
    if (own) bits.push(`<span class="badge own">${escapeHtml(t('ipMark.own'))}</span>`)
    if (inSpf) bits.push(`<span class="badge spf">${escapeHtml(t('ipMark.spf'))}</span>`)
  }
  if (meta?.countryCode || meta?.country) {
    const geo = [meta.countryCode, meta.city].filter(Boolean).join(' · ')
    bits.push(`<span class="badge">${escapeHtml(geo || meta.country || '')}</span>`)
  }
  if (meta?.asn != null) {
    bits.push(`<span class="badge">AS${meta.asn}</span>`)
  }
  if (meta?.cloudProvider) {
    bits.push(`<span class="badge cloud">${escapeHtml(meta.cloudProvider)}</span>`)
  } else if (provider) {
    bits.push(`<span class="badge">${escapeHtml(provider)}</span>`)
  }
  const blockHits = (meta?.dnsblHits ?? []).filter((h) => h !== 'dnswl')
  const whiteHits = (meta?.dnsblHits ?? []).filter((h) => h === 'dnswl')
  for (const hit of blockHits) {
    bits.push(`<span class="badge bad">${escapeHtml(hit)}</span>`)
  }
  for (const hit of whiteHits) {
    bits.push(`<span class="badge">${escapeHtml(hit)}</span>`)
  }
  if (ptr) bits.push(`<span class="ptr">${escapeHtml(ptr)}</span>`)
  return bits.length ? `<div class="ip-meta">${bits.join(' ')}</div>` : ''
}

export function formatIpCellHtml(
  ip: string,
  fallbackProvider?: string | null,
  fallbackPtr?: string | null,
  options: { includeMeta?: boolean } = {}
): string {
  const includeMeta = options.includeMeta !== false
  return `<span class="ip-cell">
    <span class="ip-cell-head mono">
      <span>${escapeHtml(ip)}</span><button type="button" class="ip-detail-btn" data-ip-detail="${escapeHtml(ip)}" title="${escapeHtml(t('ipDetail.openHint'))}" aria-label="${escapeHtml(t('ipDetail.openHint'))}">i</button>
    </span>
    ${includeMeta ? formatIpMetaHtml(ip, fallbackProvider, fallbackPtr) : ''}
  </span>`
}
