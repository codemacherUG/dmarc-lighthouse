import { normalizeLocale, setLocale, t, type AppLocale, type MessageKey } from '../../shared/i18n'
import type { AnalyzeProgress, UpdateStatusPayload } from '../../shared/types'
import { updateChartLocaleLabels } from './charts'
import {
  accountSelectEl,
  btnCheckUpdate,
  btnDns,
  btnFetch,
  btnInfo,
  btnOpenFiles,
  btnSettings,
  btnTest,
  btnUpdateDismiss,
  btnUpdateInstall,
  infoDialog,
  languageEl,
  progressEl,
  progressLabelEl,
  statusEl,
  updateBanner,
  updateBannerText,
  updateCheckStatusEl
} from './dom'
import { state } from './state'

/** Called after locale strings/charts are updated so view/settings can refresh. */
let afterLocaleChange: (() => void) | null = null

export function setAfterLocaleChange(fn: () => void): void {
  afterLocaleChange = fn
}

export function setStatus(message: string, kind: 'ok' | 'error' | '' = ''): void {
  statusEl.textContent = message
  statusEl.classList.remove('ok', 'error')
  if (kind) statusEl.classList.add(kind)
}

export function showUpdateBanner(text: string, showInstall: boolean): void {
  updateBannerText.textContent = text
  updateBanner.classList.remove('hidden', 'error', 'ready')
  if (showInstall) updateBanner.classList.add('ready')
  btnUpdateInstall.classList.toggle('hidden', !showInstall)
}

export function hideUpdateBanner(): void {
  updateBanner.classList.add('hidden')
  btnUpdateInstall.classList.add('hidden')
}

export function applyUpdateStatus(payload: UpdateStatusPayload): void {
  switch (payload.status) {
    case 'checking':
      updateCheckStatusEl.textContent = t('update.checking')
      break
    case 'available':
      showUpdateBanner(t('update.available', { version: payload.version }), false)
      updateCheckStatusEl.textContent = t('update.availableShort', { version: payload.version })
      break
    case 'downloading': {
      const pct = Math.max(0, Math.min(100, Math.round(payload.percent)))
      showUpdateBanner(t('update.downloading', { percent: pct }), false)
      updateCheckStatusEl.textContent = t('update.downloadShort', { percent: pct })
      break
    }
    case 'downloaded':
      showUpdateBanner(t('update.downloaded', { version: payload.version }), true)
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

export function applyProgress(progress: AnalyzeProgress): void {
  const pct =
    progress.total > 0 ? Math.min(100, Math.round((progress.processed / progress.total) * 100)) : 0
  progressEl.value = progress.phase === 'done' ? 100 : pct
  progressLabelEl.textContent = progress.message ?? progress.phase
  if (progress.phase === 'error') {
    setStatus(progress.message ?? t('app.error'), 'error')
  } else if (progress.message) {
    setStatus(progress.message)
  }
}

export function initChrome(): void {
  btnCheckUpdate.addEventListener('click', async () => {
    updateCheckStatusEl.textContent = t('update.checking')
    try {
      const result = await window.api.checkForUpdates()
      if (!result.ok) updateCheckStatusEl.textContent = result.message
    } catch (err) {
      updateCheckStatusEl.textContent = err instanceof Error ? err.message : String(err)
    }
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
}
