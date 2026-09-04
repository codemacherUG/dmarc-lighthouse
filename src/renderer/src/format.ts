import { isAuthorizedSender } from '../../shared/ipcidr'
import type { CloudPrefix } from '../../shared/ipcidr'
import { getLocale, t } from '../../shared/i18n'
import { matchSendingService } from '../../shared/sending-services'
import type { IpInfo } from '../../shared/types'
import { state } from './state'

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

function metaBadge(label: string, tooltip: string, variant = ''): string {
  const classes = ['badge', variant].filter(Boolean).join(' ')
  return `<span class="${classes}" title="${escapeHtml(tooltip)}">${escapeHtml(label)}</span>`
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
  fallbackPtr?: string | null,
  options?: {
    groupedIpCount?: number
    spfPrefixes?: CloudPrefix[]
    spfDomain?: string | null
    sendingDomain?: string | null
    sendingDomains?: string[]
  }
): string {
  const meta = state.ipLabelCache.get(ip)
  const provider = resolveProviderLabel(meta, fallbackProvider)
  const sendingService = matchSendingService(state.sendingServices, {
    provider: meta?.provider ?? fallbackProvider ?? null,
    domain: options?.sendingDomain ?? null,
    ip,
    asn: meta?.asn
  }) ??
    (options?.sendingDomains ?? [options?.sendingDomain ?? null])
      .map((domain) =>
        matchSendingService(state.sendingServices, {
          provider: null,
          domain,
          ip,
          asn: meta?.asn
        })
      )
      .find(Boolean)
  const ptr = fallbackPtr ?? meta?.ptr
  const bits: string[] = []
  if ((options?.groupedIpCount ?? 0) > 1) {
    const count = options?.groupedIpCount ?? 0
    bits.push(metaBadge(t('problems.ipGroup', { count }), t('ipMeta.groupHint', { count })))
  }
  const spfAuthorized = options?.spfPrefixes
    ? isAuthorizedSender(ip, options.spfPrefixes)
    : isSpfSender(ip)
  if (spfAuthorized) {
    const spfHint = options?.spfDomain
      ? t('ipMeta.spfDomainHint', { domain: options.spfDomain })
      : t('ipMeta.spfHint')
    bits.push(metaBadge(t('ipMark.spf'), spfHint, 'spf'))
  }
  if (meta?.countryCode || meta?.country) {
    const geo = [meta.countryCode, meta.city].filter(Boolean).join(' · ')
    const location = geo || meta.country || ''
    bits.push(metaBadge(location, t('ipMeta.geoHint', { location })))
  }
  if (meta?.asn != null) {
    bits.push(metaBadge(`AS${meta.asn}`, t('ipMeta.asnHint')))
  }
  // The identified service ("SendGrid") is more actionable than the network it
  // runs on ("AWS"), so it leads and the cloud label only follows if it adds info.
  const senderName = sendingService?.provider ?? meta?.provider ?? null
  if (senderName) {
    const kind = sendingService ? '' : meta?.senderKind ? t(`sender.kind.${meta.senderKind}`) : ''
    const kindSuffix = kind ? ` (${kind})` : ''
    bits.push(
      metaBadge(
        senderName,
        sendingService
          ? t('ipMeta.sendingServiceHint', { provider: senderName })
          : t('ipMeta.providerHint', { provider: senderName, kind: kindSuffix })
      )
    )
    if (meta?.cloudProvider && meta.cloudProvider !== senderName) {
      bits.push(
        metaBadge(
          meta.cloudProvider,
          t('ipMeta.cloudHint', { provider: meta.cloudProvider }),
          'cloud'
        )
      )
    }
  } else if (meta?.cloudProvider) {
    bits.push(
      metaBadge(
        meta.cloudProvider,
        t('ipMeta.cloudHint', { provider: meta.cloudProvider }),
        'cloud'
      )
    )
  } else if (provider) {
    bits.push(metaBadge(provider, t('ipMeta.networkHint', { provider })))
  }
  const blockHits = (meta?.dnsblHits ?? []).filter((h) => h !== 'dnswl')
  const whiteHits = (meta?.dnsblHits ?? []).filter((h) => h === 'dnswl')
  for (const hit of blockHits) {
    bits.push(metaBadge(hit, t('ipMeta.blocklistHint', { list: hit }), 'bad'))
  }
  for (const hit of whiteHits) {
    bits.push(metaBadge(hit, t('ipMeta.allowlistHint', { list: hit })))
  }
  if (ptr) {
    bits.push(
      `<span class="ptr" title="${escapeHtml(t('ipMeta.ptrHint', { ptr }))}">PTR: ${escapeHtml(ptr)}</span>`
    )
  }
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
