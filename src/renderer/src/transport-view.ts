import { t, type MessageKey } from '../../shared/i18n'
import { MIN_MAX_AGE_SECONDS, mxMatchesPattern } from '../../shared/transport'
import type { TransportReason, TransportSecurityResult } from '../../shared/types'
import { dnsTransportEl } from './dom'
import { escapeHtml } from './format'

const STATUS_BADGE: Record<TransportSecurityResult['status'], string> = {
  ok: 'badge',
  warn: 'badge warn',
  bad: 'badge bad',
  unknown: 'badge cloud'
}

function tlsRptLine(result: TransportSecurityResult): string {
  const { tlsrpt } = result
  if (!tlsrpt.found) {
    const detail = tlsrpt.error ? ` (${tlsrpt.error})` : ''
    return `<span class="fail">${escapeHtml(t('transport.tlsrptMissing'))}${escapeHtml(detail)}</span>`
  }
  return `<span class="pass">${escapeHtml(
    t('transport.tlsrptFound', { rua: tlsrpt.rua.join(', ') || '—' })
  )}</span>`
}

function mark(value: string, level: 'warn' | 'bad' | null): string {
  const text = escapeHtml(value)
  if (!level) return text
  return `<span class="${level === 'bad' ? 'fail' : 'warn'}">${text}</span>`
}

function mtaStsLines(result: TransportSecurityResult): string[] {
  const { mtaSts, dane } = result
  if (!mtaSts.found) {
    const detail = mtaSts.error ? ` (${mtaSts.error})` : ''
    return [
      `<span class="fail">${escapeHtml(t('transport.mtaStsMissing'))}${escapeHtml(detail)}</span>`
    ]
  }
  const lines: string[] = []
  if (mtaSts.policy) {
    const mode = mtaSts.policy.mode
    const maxAge = mtaSts.policy.maxAgeSeconds
    const modeLevel = mode === 'testing' || mode === 'none' ? 'warn' : null
    const ageLevel = maxAge != null && maxAge < MIN_MAX_AGE_SECONDS ? 'warn' : null
    lines.push(
      t('transport.mtaStsFound', {
        mode: mark(mode ?? '—', modeLevel),
        id: escapeHtml(mtaSts.id ?? '—'),
        maxAge: mark(maxAge == null ? '—' : String(maxAge), ageLevel)
      })
    )
    if (mtaSts.policy.mx.length > 0) {
      const hosts = dane.mx.map((m) => m.host)
      const uncovered =
        hosts.length > 0 &&
        hosts.some((host) => !mtaSts.policy!.mx.some((pattern) => mxMatchesPattern(host, pattern)))
      const mxLevel = uncovered ? (mode === 'enforce' ? 'bad' : 'warn') : null
      const mxText = t('transport.mtaStsMx', { mx: mtaSts.policy.mx.join(', ') })
      lines.push(`<span class="mono">${mark(mxText, mxLevel)}</span>`)
    }
  } else {
    lines.push(
      `<span class="fail">${escapeHtml(
        t('transport.mtaStsPolicyError', { message: mtaSts.policyError ?? '—' })
      )}</span>`
    )
  }
  return lines
}

function daneLines(result: TransportSecurityResult): string[] {
  const { dane } = result
  if (dane.mx.length === 0) {
    const detail = dane.error ? ` (${dane.error})` : ''
    return [`${escapeHtml(t('transport.mxNone'))}${escapeHtml(detail)}`]
  }
  return dane.mx.map((mx) => {
    const state = mx.found
      ? `<span class="pass">${escapeHtml(t('transport.daneFound', { count: mx.tlsa.length }))}</span>`
      : `<span class="muted">${escapeHtml(mx.error ? t('transport.daneError') : t('transport.daneMissing'))}</span>`
    return t('transport.daneLine', {
      host: `<span class="mono">${escapeHtml(mx.host)}</span>`,
      state
    })
  })
}

function reasonClass(reason: TransportReason): string {
  if (reason.level === 'ok') return 'transport-reason'
  return `transport-reason ${reason.level}`
}

export function renderTransportSecurity(result: TransportSecurityResult): void {
  const reasons = result.reasons
    .map(
      (reason) =>
        `<li class="${reasonClass(reason)}">${escapeHtml(t(reason.key as MessageKey))}</li>`
    )
    .join('')
  dnsTransportEl.innerHTML = `
    <div class="transport-head">
      <strong>${escapeHtml(t('transport.title'))}</strong>
      <span class="${STATUS_BADGE[result.status]}">${escapeHtml(t(`transport.status.${result.status}` as MessageKey))}</span>
    </div>
    <div class="transport-block">
      <span class="transport-label">${escapeHtml(t('transport.tlsrpt'))}</span>
      <div>${tlsRptLine(result)}</div>
    </div>
    <div class="transport-block">
      <span class="transport-label">${escapeHtml(t('transport.mtaSts'))}</span>
      <div>${mtaStsLines(result).join('<br />')}</div>
    </div>
    <div class="transport-block">
      <span class="transport-label">${escapeHtml(t('transport.dane'))}</span>
      <div>${daneLines(result).join('<br />')}</div>
    </div>
    <ul class="transport-reasons">${reasons}</ul>`
  dnsTransportEl.classList.remove('hidden')
}

/** Runs alongside the DNS check; failures stay contained in this block. */
export async function runTransportCheck(domain: string): Promise<void> {
  dnsTransportEl.classList.remove('hidden')
  dnsTransportEl.innerHTML = `<p class="muted">${escapeHtml(t('transport.checking', { domain }))}</p>`
  try {
    renderTransportSecurity(await window.api.checkTransport(domain))
  } catch (err) {
    dnsTransportEl.innerHTML = `<p class="fail">${escapeHtml(
      t('transport.error', { message: err instanceof Error ? err.message : String(err) })
    )}</p>`
  }
}
