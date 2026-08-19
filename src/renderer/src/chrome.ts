import { normalizeLocale, setLocale, t, type AppLocale, type MessageKey } from '../../shared/i18n'
import type { AnalyzeProgress, UpdateStatusPayload } from '../../shared/types'
import { updateChartLocaleLabels } from './charts'
import {
  accountSelectEl,
  btnCheckUpdate,
  btnCloseStatusLog,
  btnDns,
  btnFetch,
  btnInfo,
  btnOpenFiles,
  btnOpenLicenses,
  btnSettings,
  btnStatusLog,
  btnStatusLogOk,
  btnTest,
  btnUpdateDismiss,
  btnUpdateDownload,
  btnUpdateInstall,
  btnCloseDns,
  dnsDialog,
  dnsDomainEl,
  infoDialog,
  languageEl,
  navDns,
  navTools,
  progressEl,
  progressLabelEl,
  statusEl,
  statusLogDialog,
  statusLogListEl,
  toolsMenu,
  topProgressEl,
  updateBanner,
  updateBannerText,
  updateCheckStatusEl
} from './dom'
import { escapeHtml } from './format'
import { state } from './state'

/** Called after locale strings/charts are updated so view/settings can refresh. */
let afterLocaleChange: (() => void) | null = null

export function setAfterLocaleChange(fn: () => void): void {
  afterLocaleChange = fn
}

type StatusKind = 'ok' | 'error' | ''

type StatusEntry = {
  message: string
  kind: StatusKind
}

const MAX_STATUS_ITEMS = 40
const statusHistory: StatusEntry[] = []

function renderStatusLog(): void {
  if (statusHistory.length === 0) {
    statusLogListEl.innerHTML = `<li class="status-item empty">${escapeHtml(t('status.logEmpty'))}</li>`
    return
  }
  statusLogListEl.innerHTML = statusHistory
    .map((entry) => {
      const cls = entry.kind ? `status-item ${entry.kind}` : 'status-item'
      return `<li class="${cls}">${escapeHtml(entry.message)}</li>`
    })
    .join('')
  statusLogListEl.scrollTop = statusLogListEl.scrollHeight
}

export function setStatus(message: string, kind: StatusKind = ''): void {
  const last = statusHistory[statusHistory.length - 1]
  if (last?.message === message && last.kind === kind) {
    statusEl.textContent = message
    statusEl.classList.remove('ok', 'error')
    if (kind) statusEl.classList.add(kind)
    return
  }

  statusHistory.push({ message, kind })
  while (statusHistory.length > MAX_STATUS_ITEMS) statusHistory.shift()

  statusEl.textContent = message
  statusEl.classList.remove('ok', 'error')
  if (kind) statusEl.classList.add(kind)

  if (statusLogDialog.open) renderStatusLog()
}

type UpdateBannerAction = 'none' | 'download' | 'install'

export function showUpdateBanner(text: string, action: UpdateBannerAction = 'none'): void {
  updateBannerText.textContent = text
  updateBanner.classList.remove('hidden', 'error')
  updateBanner.classList.toggle('ready', action !== 'none')
  btnUpdateDownload.disabled = false
  btnUpdateDownload.classList.toggle('hidden', action !== 'download')
  btnUpdateInstall.classList.toggle('hidden', action !== 'install')
}

export function hideUpdateBanner(): void {
  updateBanner.classList.add('hidden')
  btnUpdateDownload.classList.add('hidden')
  btnUpdateInstall.classList.add('hidden')
}

export function applyUpdateStatus(payload: UpdateStatusPayload): void {
  switch (payload.status) {
    case 'checking':
      updateCheckStatusEl.textContent = t('update.checking')
      break
    case 'available':
      showUpdateBanner(t('update.available', { version: payload.version }), 'download')
      updateCheckStatusEl.textContent = t('update.availableShort', { version: payload.version })
      break
    case 'downloading': {
      const pct = Math.max(0, Math.min(100, Math.round(payload.percent)))
      showUpdateBanner(t('update.downloading', { percent: pct }))
      updateCheckStatusEl.textContent = t('update.downloadShort', { percent: pct })
      break
    }
    case 'verifying':
      showUpdateBanner(t('update.verifying', { version: payload.version }))
      updateCheckStatusEl.textContent = t('update.verifyingShort')
      break
    case 'downloaded':
      showUpdateBanner(t('update.downloaded', { version: payload.version }), 'install')
      updateCheckStatusEl.textContent = t('update.downloadedShort', { version: payload.version })
      break
    case 'not-available':
      updateCheckStatusEl.textContent = payload.version
        ? t('update.noneVersion', { version: payload.version })
        : t('update.none')
      break
    case 'error':
      updateBannerText.textContent = t('update.error', { message: payload.message })
      updateBanner.classList.remove('hidden', 'ready')
      updateBanner.classList.add('error')
      btnUpdateDownload.classList.add('hidden')
      btnUpdateInstall.classList.add('hidden')
      updateCheckStatusEl.textContent = payload.message
      break
  }
}

export function applyDomI18n(): void {
  for (const el of document.querySelectorAll<HTMLElement>('[data-i18n]')) {
    const key = el.dataset.i18n as MessageKey | undefined
    if (key) el.textContent = t(key)
  }
  for (const el of document.querySelectorAll<HTMLElement>('[data-i18n-placeholder]')) {
    const key = el.dataset.i18nPlaceholder as MessageKey | undefined
    if (key) (el as HTMLInputElement).placeholder = t(key)
  }
  for (const el of document.querySelectorAll<HTMLElement>('[data-i18n-title]')) {
    const key = el.dataset.i18nTitle as MessageKey | undefined
    if (key) el.title = t(key)
  }
  for (const el of document.querySelectorAll<HTMLElement>('[data-i18n-aria]')) {
    const key = el.dataset.i18nAria as MessageKey | undefined
    if (key) el.setAttribute('aria-label', t(key))
  }
}

export function applyUiLocale(locale: AppLocale): void {
  setLocale(locale)
  document.documentElement.lang = locale
  applyDomI18n()
  updateChartLocaleLabels()
  afterLocaleChange?.()
}

export function setBusy(next: boolean): void {
  state.busy = next
  btnFetch.disabled = next
  btnSettings.disabled = next
  btnTest.disabled = next
  btnOpenFiles.disabled = next
  btnDns.disabled = next
  accountSelectEl.disabled = next
}

/** Update the fixed top progress line (0–100). Pass null for indeterminate. */
export function setTopProgress(pct: number | null, active = true): void {
  const indeterminate = pct == null
  const value = indeterminate ? 0 : Math.max(0, Math.min(100, pct))
  progressEl.style.width = `${value}%`
  topProgressEl.classList.toggle('active', active)
  topProgressEl.classList.toggle('indeterminate', active && indeterminate)
  topProgressEl.setAttribute('aria-hidden', active ? 'false' : 'true')
  topProgressEl.setAttribute('aria-valuenow', indeterminate ? '0' : String(value))
}

export function applyProgress(progress: AnalyzeProgress): void {
  const pct =
    progress.total > 0 ? Math.min(100, Math.round((progress.processed / progress.total) * 100)) : 0
  const done = progress.phase === 'done'
  const errored = progress.phase === 'error'
  if (done || errored) {
    setTopProgress(done ? 100 : 0, false)
  } else if (progress.total > 0) {
    setTopProgress(pct, true)
  } else {
    setTopProgress(null, true)
  }
  progressLabelEl.textContent = progress.message ?? (done || errored ? '' : progress.phase)
  if (errored) {
    setStatus(progress.message ?? t('app.error'), 'error')
    progressLabelEl.textContent = ''
  } else if (done && progress.message) {
    setStatus(progress.message, 'ok')
    progressLabelEl.textContent = ''
  }
}

export function initChrome(): void {
  setStatus(t('app.ready'))

  const openStatusLog = (): void => {
    renderStatusLog()
    statusLogDialog.showModal()
  }
  const closeStatusLog = (): void => statusLogDialog.close()
  btnStatusLog.addEventListener('click', openStatusLog)
  btnCloseStatusLog.addEventListener('click', closeStatusLog)
  btnStatusLogOk.addEventListener('click', closeStatusLog)

  btnCheckUpdate.addEventListener('click', async () => {
    updateCheckStatusEl.textContent = t('update.checking')
    try {
      const result = await window.api.checkForUpdates()
      if (!result.ok) updateCheckStatusEl.textContent = result.message
    } catch (err) {
      updateCheckStatusEl.textContent = err instanceof Error ? err.message : String(err)
    }
  })

  btnOpenLicenses.addEventListener('click', async () => {
    updateCheckStatusEl.textContent = ''
    try {
      const result = await window.api.openThirdPartyNotices()
      if (!result.ok) updateCheckStatusEl.textContent = result.message
    } catch (err) {
      updateCheckStatusEl.textContent = err instanceof Error ? err.message : String(err)
    }
  })

  btnUpdateDownload.addEventListener('click', () => {
    btnUpdateDownload.disabled = true
    void window.api.downloadUpdate().then(
      (result) => {
        if (!result.ok) {
          btnUpdateDownload.disabled = false
          updateCheckStatusEl.textContent = result.message
        }
      },
      (err: unknown) => {
        btnUpdateDownload.disabled = false
        updateCheckStatusEl.textContent = err instanceof Error ? err.message : String(err)
      }
    )
  })

  btnUpdateInstall.addEventListener('click', () => {
    void window.api.installUpdate()
  })

  btnUpdateDismiss.addEventListener('click', () => hideUpdateBanner())

  languageEl.addEventListener('change', () => {
    applyUiLocale(normalizeLocale(languageEl.value))
  })

  window.api.onUpdateStatus(applyUpdateStatus)

  btnInfo.addEventListener('click', () => {
    updateCheckStatusEl.textContent = ''
    infoDialog.showModal()
  })

  const setToolsMenuOpen = (open: boolean): void => {
    toolsMenu.hidden = !open
    navTools.setAttribute('aria-expanded', String(open))
  }

  navTools.addEventListener('click', (event) => {
    event.stopPropagation()
    setToolsMenuOpen(toolsMenu.hasAttribute('hidden'))
  })

  toolsMenu.addEventListener('click', () => setToolsMenuOpen(false))

  document.addEventListener('click', (event) => {
    if (toolsMenu.hasAttribute('hidden')) return
    const target = event.target
    if (!(target instanceof Node)) return
    if (navTools.contains(target) || toolsMenu.contains(target)) return
    setToolsMenuOpen(false)
  })

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && !toolsMenu.hasAttribute('hidden')) setToolsMenuOpen(false)
  })

  const openDnsDialog = (): void => {
    if (!dnsDialog.open) dnsDialog.showModal()
    queueMicrotask(() => {
      dnsDomainEl.focus()
      dnsDomainEl.select()
    })
  }

  navDns.addEventListener('click', () => openDnsDialog())
  btnCloseDns.addEventListener('click', () => dnsDialog.close())
}
