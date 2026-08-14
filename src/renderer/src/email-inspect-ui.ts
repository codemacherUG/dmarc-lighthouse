import { t, type MessageKey } from '../../shared/i18n'
import type {
  EmailHop,
  EmailIdentity,
  EmailInspectCheck,
  EmailInspectResponse,
  EmailInspectResult,
  EmailInspectStatus
} from '../../shared/types'
import {
  btnCloseEmailInspect,
  btnEmailInspect,
  btnEmailInspectOpen,
  btnEmailInspectPaste,
  btnEmailInspectPdf,
  emailInspectDialog,
  emailInspectPasteEl,
  emailInspectResultEl
} from './dom'
import { escapeHtml } from './format'
import { setStatus } from './chrome'

const STATUS_BADGE: Record<EmailInspectStatus, string> = {
  ok: 'badge',
  warn: 'badge warn',
  bad: 'badge bad',
  unknown: 'badge cloud'
}

let lastResult: EmailInspectResult | null = null
let lastError: string | null = null

function statusLabel(status: EmailInspectStatus): string {
  return t(`email.status.${status}` as MessageKey)
}

function identityRow(labelKey: MessageKey, value: string | null, extra?: string | null): string {
  if (!value) return ''
  const extraHtml = extra ? ` <span class="muted">${escapeHtml(extra)}</span>` : ''
  return `<div class="email-id-row"><dt>${escapeHtml(t(labelKey))}</dt><dd><span class="mono">${escapeHtml(value)}</span>${extraHtml}</dd></div>`
}

function identityHtml(identity: EmailIdentity): string {
  const fromExtra = identity.fromDisplay ? identity.fromDisplay : null
  return `<dl class="email-identity">
    ${identityRow('email.from', identity.from, fromExtra)}
    ${identityRow('email.returnPath', identity.returnPath)}
    ${identityRow('email.replyTo', identity.replyTo)}
    ${identityRow('email.to', identity.to)}
    ${identityRow('email.subject', identity.subject)}
    ${identityRow('email.date', identity.date)}
    ${identityRow('email.messageId', identity.messageId)}
  </dl>`
}

function hopMeta(hop: EmailHop): string {
  const info = hop.ipInfo
  const bits: string[] = []
  if (hop.fromIp) bits.push(`<span class="mono">${escapeHtml(hop.fromIp)}</span>`)
  const geo = [info?.countryCode, info?.city].filter(Boolean).join(' · ')
  if (geo) bits.push(`<span class="badge">${escapeHtml(geo)}</span>`)
  const provider = info?.provider || info?.cloudProvider || info?.asOrg
  if (provider) bits.push(`<span class="badge">${escapeHtml(provider)}</span>`)
  if (hop.tlsVersion) {
    bits.push(`<span class="badge">${escapeHtml(hop.tlsVersion)}</span>`)
  } else if (hop.withTls) {
    bits.push(`<span class="badge">${escapeHtml(t('email.tlsImplied'))}</span>`)
  } else if (hop.local) {
    bits.push(`<span class="badge">${escapeHtml(t('email.hopLocal'))}</span>`)
  } else {
    bits.push(`<span class="badge warn">${escapeHtml(t('email.noTls'))}</span>`)
  }
  if (hop.protocol) bits.push(`<span class="badge">${escapeHtml(hop.protocol)}</span>`)
  return bits.join(' ')
}

function hopsHtml(hops: EmailHop[]): string {
  if (hops.length === 0) {
    return `<p class="muted">${escapeHtml(t('email.hopsEmpty'))}</p>`
  }
  const items = hops
    .map((hop) => {
      const host = hop.fromHost || hop.fromIp || '—'
      const by = hop.byHost
        ? `<div class="muted">${escapeHtml(t('email.hopBy', { host: hop.byHost }))}</div>`
        : ''
      const when = hop.timestamp
        ? `<div class="muted">${escapeHtml(hop.timestamp.replace('T', ' ').replace(/\.\d+Z$/, ' UTC'))}</div>`
        : ''
      return `<li class="email-hop ${hop.withTls || hop.local ? '' : 'no-tls'}">
        <span class="email-hop-index">${hop.index}</span>
        <div class="email-hop-body">
          <strong>${escapeHtml(host)}</strong>
          <div class="email-hop-meta">${hopMeta(hop)}</div>
          ${by}${when}
        </div>
      </li>`
    })
    .join('')
  return `<ol class="email-hops">${items}</ol>`
}

function checkHtml(item: EmailInspectCheck): string {
  return `<li class="email-check ${item.status}">
    <span class="${STATUS_BADGE[item.status]}">${escapeHtml(statusLabel(item.status))}</span>
    <div>
      <strong>${escapeHtml(t(item.titleKey as MessageKey))}</strong>
      <p>${escapeHtml(t(item.detailKey as MessageKey, item.params))}</p>
    </div>
  </li>`
}

function extrasHtml(result: EmailInspectResult): string {
  const parts: string[] = []
  if (result.dkimSignatures.length > 0) {
    const items = result.dkimSignatures
      .map((sig) => {
        const line = t('email.dkimSig', {
          selector: sig.selector || '—',
          domain: sig.domain || '—'
        })
        return `<li class="mono">${escapeHtml(line)}</li>`
      })
      .join('')
    parts.push(
      `<section class="email-inspect-section"><h4>${escapeHtml(t('email.signatures'))}</h4><ul class="email-inspect-list">${items}</ul></section>`
    )
  }
  if (result.arc.length > 0) {
    const items = result.arc
      .map(
        (set) =>
          `<li class="mono">${escapeHtml(
            t('email.arcItem', { instance: set.instance, cv: set.cv || '—' })
          )}</li>`
      )
      .join('')
    parts.push(
      `<section class="email-inspect-section"><h4>${escapeHtml(t('email.arcTitle'))}</h4><ul class="email-inspect-list">${items}</ul></section>`
    )
  }
  return parts.join('')
}

function syncPdfButton(): void {
  btnEmailInspectPdf.disabled = !lastResult
}

function renderResult(result: EmailInspectResult): void {
  emailInspectResultEl.innerHTML = `
    <div class="email-verdict ${result.status}">
      <span class="email-verdict-file">${escapeHtml(t('email.fileName'))}: ${escapeHtml(result.fileName)}</span>
      <h3>${escapeHtml(t(result.verdictKey as MessageKey))}</h3>
      <span class="${STATUS_BADGE[result.status]}">${escapeHtml(statusLabel(result.status))}</span>
    </div>
    <section class="email-inspect-section">
      <h4>${escapeHtml(t('email.identity'))}</h4>
      ${identityHtml(result.identity)}
    </section>
    <section class="email-inspect-section">
      <h4>${escapeHtml(t('email.checks'))}</h4>
      <ul class="email-checks">${result.checks.map(checkHtml).join('')}</ul>
    </section>
    <section class="email-inspect-section">
      <h4>${escapeHtml(t('email.hops'))}</h4>
      <p class="hint">${escapeHtml(t('email.hopsHint'))}</p>
      ${hopsHtml(result.hops)}
    </section>
    ${extrasHtml(result)}`
}

function renderEmpty(): void {
  emailInspectResultEl.innerHTML = `<p class="muted email-inspect-placeholder">${escapeHtml(t('email.empty'))}</p>`
}

function renderError(message: string): void {
  emailInspectResultEl.innerHTML = `<p class="fail">${escapeHtml(t('email.error', { message }))}</p>`
}

function show(response: EmailInspectResponse): void {
  if (!response.ok) {
    lastResult = null
    lastError = response.message
    renderError(response.message)
    syncPdfButton()
    return
  }
  lastError = null
  lastResult = response.result
  renderResult(response.result)
  syncPdfButton()
}

export function isEmailInspectOpen(): boolean {
  return emailInspectDialog.open
}

export async function inspectDroppedFile(file: File): Promise<void> {
  const data = await file.arrayBuffer()
  show(await window.api.parseEmail({ name: file.name, data }))
}

export function openEmailInspect(): void {
  emailInspectDialog.showModal()
  if (lastResult) renderResult(lastResult)
  else if (lastError) renderError(lastError)
  else renderEmpty()
}

/** Seed a result for screenshot capture (no file dialog). */
export function seedEmailInspect(result: EmailInspectResult): void {
  lastError = null
  lastResult = result
  if (emailInspectDialog.open) renderResult(result)
  syncPdfButton()
}

export function refreshEmailInspectLocale(): void {
  if (!emailInspectDialog.open) return
  if (lastResult) renderResult(lastResult)
  else if (lastError) renderError(lastError)
  else renderEmpty()
}

export function initEmailInspectUi(): void {
  btnEmailInspect.addEventListener('click', () => openEmailInspect())
  btnCloseEmailInspect.addEventListener('click', () => emailInspectDialog.close())
  syncPdfButton()

  btnEmailInspectPdf.addEventListener('click', async () => {
    if (!lastResult) {
      setStatus(t('email.pdfEmpty'), 'error')
      return
    }
    btnEmailInspectPdf.disabled = true
    setStatus(t('status.emailPdfBuilding'))
    try {
      const res = await window.api.exportEmailInspectPdf(lastResult)
      setStatus(res.message, res.ok ? 'ok' : '')
    } catch (err) {
      setStatus(err instanceof Error ? err.message : String(err), 'error')
    } finally {
      syncPdfButton()
    }
  })

  btnEmailInspectOpen.addEventListener('click', async () => {
    btnEmailInspectOpen.disabled = true
    try {
      const response = await window.api.openEmailFile()
      if (response) show(response)
    } catch (err) {
      show({ ok: false, message: err instanceof Error ? err.message : String(err) })
    } finally {
      btnEmailInspectOpen.disabled = false
    }
  })

  btnEmailInspectPaste.addEventListener('click', async () => {
    const text = emailInspectPasteEl.value
    btnEmailInspectPaste.disabled = true
    try {
      show(await window.api.parseEmail({ text, name: 'paste.eml' }))
    } catch (err) {
      show({ ok: false, message: err instanceof Error ? err.message : String(err) })
    } finally {
      btnEmailInspectPaste.disabled = false
    }
  })

  emailInspectDialog.addEventListener('dragover', (event) => {
    event.preventDefault()
    event.stopPropagation()
  })
  emailInspectDialog.addEventListener('drop', (event) => {
    event.preventDefault()
    event.stopPropagation()
    const file = event.dataTransfer?.files[0]
    if (file) void inspectDroppedFile(file)
  })
}
