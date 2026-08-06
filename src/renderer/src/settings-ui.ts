import { suggestAccountName } from '../../shared/account'
import { normalizeLocale, t } from '../../shared/i18n'
import type {
  AccountPublic,
  AccountSettingsInput,
  AuthMode,
  GlobalSettings,
  ProviderPreset,
  SettingsPublic
} from '../../shared/types'
import { PROVIDER_PRESETS } from '../../shared/types'
import { applyUiLocale, setBusy, setStatus } from './chrome'
import {
  accountLabelEl,
  accountFieldEl,
  accountNameEl,
  accountSelectEl,
  archiveMailboxEl,
  authModeEl,
  autoFetchMinutesEl,
  btnCancelCreateMailbox,
  btnClearArchiveMailbox,
  btnClearCache,
  btnCloseCreateMailbox,
  btnCloseInfo,
  btnCloseSettings,
  btnConfirmCreateMailbox,
  btnDeleteAccount,
  btnDownloadGeolite,
  btnInfoOk,
  btnNewAccount,
  btnOauthDisconnect,
  btnOauthLogin,
  btnSettings,
  btnTest,
  cloudRangesEnabledEl,
  filterHideGoogleNoiseEl,
  createMailboxDialog,
  createMailboxPathEl,
  createMailboxStatusEl,
  dnsblEnabledEl,
  enrichmentEnabledEl,
  geoIpOnlineFallbackEl,
  geoliteStatusEl,
  hostEl,
  ignoredSourcesEl,
  infoDialog,
  languageEl,
  mailboxEl,
  markSeenAfterFetchEl,
  maxmindLicenseKeyEl,
  notifyNewSourceEl,
  notifyOnFailEl,
  oauthActionsEl,
  oauthGoogleClientIdEl,
  oauthHintEl,
  oauthMicrosoftClientIdEl,
  openAtLoginEl,
  passRateAlertThresholdEl,
  passwordEl,
  passwordFieldEl,
  passwordHintEl,
  portEl,
  providerEl,
  rdapEnabledEl,
  runInTrayEl,
  secureEl,
  settingsAccountSelectEl,
  settingsDialog,
  settingsForm,
  settingsStatusEl,
  subjectFilterEl,
  tabAccountEl,
  tabBtnAccount,
  tabBtnEnrichment,
  tabBtnGeneral,
  tabEnrichmentEl,
  tabGeneralEl,
  userEl
} from './dom'
import { escapeHtml } from './format'
import { state } from './state'
import { applyView } from './view'

export const NEW_ACCOUNT_VALUE = '__new__'

type SettingsTab = 'account' | 'general' | 'enrichment'

/** Input that opened the create-mailbox dialog (mailbox or archive). */
let createMailboxTarget: HTMLInputElement | null = null
let createMailboxBusy = false
/** Full IMAP folder list for the custom picker (never filtered by the input value). */
let mailboxPaths: string[] = []
let mailboxLoadToken = 0
let mailboxRefreshTimer: ReturnType<typeof setTimeout> | null = null

/** Wired from actions to avoid settings-ui → actions cycle. */
let switchActiveAccountFn: ((id: string) => Promise<void>) | null = null

export function setSwitchActiveAccount(fn: (id: string) => Promise<void>): void {
  switchActiveAccountFn = fn
}

export function activeAccount(): AccountPublic | null {
  if (!state.settings) return null
  return state.settings.accounts.find((a) => a.id === state.settings?.activeAccountId) ?? null
}

export function dialogAccount(): AccountPublic | null {
  if (!state.settings || state.dialogAccountId == null) return null
  return state.settings.accounts.find((a) => a.id === state.dialogAccountId) ?? null
}

export function updateAccountNamePlaceholder(): void {
  accountNameEl.placeholder = suggestAccountName(userEl.value, hostEl.value)
}

export function accountHasAuth(account: AccountPublic | null | undefined): boolean {
  return Boolean(account && account.user && (account.hasPassword || account.hasOAuth))
}

export function syncAuthModeUi(): void {
  const oauth = authModeEl.value === 'oauth'
  const provider = providerEl.value
  const oauthSupported = provider === 'gmail' || provider === 'outlook' || provider === 'microsoft'
  passwordFieldEl.classList.toggle('hidden', oauth)
  oauthActionsEl.classList.toggle('hidden', !oauth)
  oauthHintEl.classList.toggle('hidden', !oauth)
  btnOauthLogin.disabled = !oauth || !oauthSupported || state.dialogAccountId == null
  btnOauthDisconnect.disabled =
    !oauth || state.dialogAccountId == null || !dialogAccount()?.hasOAuth
  if (oauth && !oauthSupported) {
    passwordHintEl.textContent = t('oauth.providerUnsupported')
  }
}

export function readAccountForm(): AccountSettingsInput {
  return {
    id: state.dialogAccountId,
    name: (accountNameEl.value ?? '').trim(),
    provider: providerEl.value as ProviderPreset,
    authMode: (authModeEl.value === 'oauth' ? 'oauth' : 'password') as AuthMode,
    host: hostEl.value.trim(),
    port: Number(portEl.value) || 993,
    secure: secureEl.checked,
    user: userEl.value.trim(),
    password: passwordEl.value,
    mailbox: mailboxEl.value.trim() || 'INBOX',
    archiveMailbox: archiveMailboxEl.value.trim(),
    subjectFilter: subjectFilterEl.value,
    markSeenAfterFetch: markSeenAfterFetchEl.checked
  }
}

export function fillMailboxOptions(paths: string[]): void {
  mailboxPaths = [...new Set(paths.map((p) => p.trim()).filter(Boolean))].sort((a, b) =>
    a.localeCompare(b, undefined, { sensitivity: 'base' })
  )
  for (const input of [mailboxEl, archiveMailboxEl]) {
    const menu = input.parentElement?.querySelector<HTMLUListElement>('[data-mailbox-menu]')
    if (menu && !menu.hidden) renderMailboxMenu(input, menu)
  }
}

function closeMailboxMenus(except?: HTMLUListElement): void {
  for (const input of [mailboxEl, archiveMailboxEl]) {
    const menu = input.parentElement?.querySelector<HTMLUListElement>('[data-mailbox-menu]')
    if (menu && menu !== except) menu.hidden = true
  }
}

function mailboxPathExists(path: string): boolean {
  const wanted = path.trim().toLowerCase()
  return Boolean(wanted) && mailboxPaths.some((p) => p.toLowerCase() === wanted)
}

function renderMailboxMenu(input: HTMLInputElement, menu: HTMLUListElement): void {
  const current = input.value.trim()
  const items = mailboxPaths.map((path) => {
    const li = document.createElement('li')
    li.setAttribute('role', 'option')
    li.textContent = path
    if (path === current) li.setAttribute('aria-selected', 'true')
    li.addEventListener('mousedown', (event) => {
      event.preventDefault()
      input.value = path
      menu.hidden = true
      input.dispatchEvent(new Event('input', { bubbles: true }))
    })
    return li
  })

  const createLi = document.createElement('li')
  createLi.className = 'mailbox-menu-action'
  createLi.setAttribute('role', 'option')
  createLi.textContent =
    current && !mailboxPathExists(current)
      ? t('settings.createMailboxNamed', { path: current })
      : t('settings.createMailbox')
  createLi.addEventListener('mousedown', (event) => {
    event.preventDefault()
    menu.hidden = true
    openCreateMailboxDialog(input)
  })
  items.push(createLi)

  menu.replaceChildren(...items)
  menu.hidden = false
  const selected = menu.querySelector<HTMLElement>('li[aria-selected="true"]')
  selected?.scrollIntoView({ block: 'nearest' })
}

function closeCreateMailboxDialog(): void {
  createMailboxBusy = false
  btnConfirmCreateMailbox.disabled = false
  createMailboxTarget = null
  if (createMailboxDialog.open) createMailboxDialog.close()
}

function openCreateMailboxDialog(input: HTMLInputElement): void {
  if (!canListMailboxes()) {
    settingsStatusEl.textContent = t('settings.needCredentials')
    return
  }
  if (typeof window.api.createMailbox !== 'function') {
    settingsStatusEl.textContent = t('enrichment.preloadRestart')
    return
  }
  createMailboxTarget = input
  createMailboxBusy = false
  btnConfirmCreateMailbox.disabled = false
  createMailboxStatusEl.textContent = ''
  createMailboxPathEl.value = input.value.trim() || 'Archive/DMARC'
  createMailboxDialog.showModal()
  queueMicrotask(() => {
    createMailboxPathEl.focus()
    createMailboxPathEl.select()
  })
}

async function confirmCreateMailbox(): Promise<void> {
  if (createMailboxBusy) return
  const input = createMailboxTarget
  const path = createMailboxPathEl.value.trim()
  if (!input) {
    closeCreateMailboxDialog()
    return
  }
  if (!path) {
    createMailboxStatusEl.textContent = t('imap.createMailboxEmpty')
    createMailboxPathEl.focus()
    return
  }
  if (typeof window.api.createMailbox !== 'function') {
    createMailboxStatusEl.textContent = t('enrichment.preloadRestart')
    return
  }

  createMailboxBusy = true
  btnConfirmCreateMailbox.disabled = true
  createMailboxStatusEl.textContent = t('settings.creatingMailbox')
  try {
    const result = await window.api.createMailbox(readAccountForm(), path)
    createMailboxStatusEl.textContent = result.message
    if (!result.ok) {
      setStatus(result.message, 'error')
      return
    }
    input.value = result.path || path
    input.dispatchEvent(new Event('input', { bubbles: true }))
    settingsStatusEl.textContent = result.message
    setStatus(result.message, 'ok')
    closeCreateMailboxDialog()
    await loadMailboxOptions({ quiet: true })
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    createMailboxStatusEl.textContent = msg
    setStatus(msg, 'error')
  } finally {
    createMailboxBusy = false
    btnConfirmCreateMailbox.disabled = false
  }
}

function openMailboxMenu(input: HTMLInputElement): void {
  const menu = input.parentElement?.querySelector<HTMLUListElement>('[data-mailbox-menu]')
  if (!menu) return
  closeMailboxMenus(menu)
  renderMailboxMenu(input, menu)
}

function isInsideMailboxCombo(target: EventTarget | null): boolean {
  const el =
    target instanceof Element ? target : target instanceof Node ? target.parentElement : null
  return Boolean(el?.closest('.mailbox-combo'))
}

function canListMailboxes(): boolean {
  const form = readAccountForm()
  if (!form.user || !form.host) return false
  if (form.password) return true
  const account = dialogAccount()
  if (form.authMode === 'oauth') return Boolean(account?.hasOAuth)
  return Boolean(account?.hasPassword)
}

/** Load IMAP folder names into the datalist. Quiet mode skips noisy global status. */
async function loadMailboxOptions(options: { quiet?: boolean } = {}): Promise<boolean> {
  const quiet = Boolean(options.quiet)
  if (!canListMailboxes()) return false
  if (typeof window.api.listMailboxes !== 'function') {
    if (!quiet) settingsStatusEl.textContent = t('enrichment.preloadRestart')
    return false
  }
  const token = ++mailboxLoadToken
  if (!quiet) settingsStatusEl.textContent = t('settings.listingMailboxes')
  try {
    const result = await window.api.listMailboxes(readAccountForm())
    if (token !== mailboxLoadToken) return false
    if (!result.ok) {
      if (!quiet) {
        settingsStatusEl.textContent = result.message
        setStatus(result.message, 'error')
      }
      return false
    }
    fillMailboxOptions(result.mailboxes.map((m) => m.path))
    settingsStatusEl.textContent = result.message
    if (!quiet) setStatus(result.message, 'ok')
    return true
  } catch (err) {
    if (token !== mailboxLoadToken) return false
    if (!quiet) {
      const msg = err instanceof Error ? err.message : String(err)
      settingsStatusEl.textContent = msg
      setStatus(msg, 'error')
    }
    return false
  }
}

export function scheduleMailboxOptionsRefresh(): void {
  if (mailboxRefreshTimer) clearTimeout(mailboxRefreshTimer)
  mailboxRefreshTimer = setTimeout(() => {
    mailboxRefreshTimer = null
    void loadMailboxOptions({ quiet: true })
  }, 150)
}

export function readGlobalForm(): GlobalSettings {
  return {
    autoFetchMinutes: Number(autoFetchMinutesEl.value) || 0,
    notifyOnFail: notifyOnFailEl.checked,
    passRateAlertThreshold: Number(passRateAlertThresholdEl.value) || 0,
    notifyNewSource: notifyNewSourceEl.checked,
    ignoredSources: ignoredSourcesEl.value,
    runInTray: runInTrayEl.checked,
    openAtLogin: openAtLoginEl.checked,
    language: normalizeLocale(languageEl.value),
    oauthGoogleClientId: oauthGoogleClientIdEl.value.trim(),
    oauthMicrosoftClientId: oauthMicrosoftClientIdEl.value.trim(),
    enrichmentEnabled: enrichmentEnabledEl.checked,
    geoIpOnlineFallback: geoIpOnlineFallbackEl.checked,
    maxmindLicenseKey: maxmindLicenseKeyEl.value.trim(),
    hasMaxmindLicenseKey: Boolean(state.settings?.global.hasMaxmindLicenseKey),
    dnsblEnabled: dnsblEnabledEl.checked,
    cloudRangesEnabled: cloudRangesEnabledEl.checked,
    rdapEnabled: rdapEnabledEl.checked,
    hideGoogleNoise: filterHideGoogleNoiseEl.checked
  }
}

function applyProviderPreset(provider: ProviderPreset): void {
  const preset = PROVIDER_PRESETS[provider]
  if (provider !== 'custom') {
    hostEl.value = preset.host
  }
  portEl.value = String(preset.port)
  secureEl.checked = preset.secure
}

export function updateAccountUi(): void {
  const account = activeAccount()
  accountLabelEl.textContent = account ? account.label : t('app.noCredentials')

  const accounts = state.settings?.accounts ?? []
  accountFieldEl.classList.toggle('hidden', accounts.length <= 1)
  accountSelectEl.innerHTML = accounts
    .map(
      (a) =>
        `<option value="${escapeHtml(a.id)}"${a.id === state.settings?.activeAccountId ? ' selected' : ''}>${escapeHtml(a.label)}</option>`
    )
    .join('')
}

export function fillAccountForm(account: AccountPublic | null): void {
  if (account) {
    // Coerce carefully: assigning undefined to input.value becomes the string "undefined".
    accountNameEl.value = account.name ?? ''
    providerEl.value = account.provider
    authModeEl.value = account.authMode === 'oauth' ? 'oauth' : 'password'
    hostEl.value = account.host
    portEl.value = String(account.port)
    secureEl.checked = account.secure
    userEl.value = account.user
    mailboxEl.value = account.mailbox
    archiveMailboxEl.value = account.archiveMailbox ?? ''
    subjectFilterEl.value = account.subjectFilter
    markSeenAfterFetchEl.checked = account.markSeenAfterFetch
  } else {
    accountNameEl.value = ''
    providerEl.value = 'custom'
    authModeEl.value = 'password'
    hostEl.value = ''
    portEl.value = '993'
    secureEl.checked = true
    userEl.value = ''
    mailboxEl.value = 'INBOX'
    archiveMailboxEl.value = ''
    subjectFilterEl.value = 'Report Domain'
    markSeenAfterFetchEl.checked = false
  }
  passwordEl.value = ''
  updateAccountNamePlaceholder()
  if (account?.authMode === 'oauth' && account.hasOAuth) {
    passwordHintEl.textContent = t('settings.oauthConnected')
  } else {
    passwordHintEl.textContent = account?.hasPassword
      ? t('settings.passwordSaved')
      : t('settings.passwordHint')
  }
  syncAuthModeUi()
  syncArchiveMailboxClear()
  settingsStatusEl.textContent = ''
}

function syncArchiveMailboxClear(): void {
  btnClearArchiveMailbox.hidden = !archiveMailboxEl.value.trim()
}

export function fillGlobalForm(global: GlobalSettings): void {
  autoFetchMinutesEl.value = String(global.autoFetchMinutes ?? 0)
  notifyOnFailEl.checked = global.notifyOnFail !== false
  notifyNewSourceEl.checked = Boolean(global.notifyNewSource)
  passRateAlertThresholdEl.value = String(global.passRateAlertThreshold ?? 0)
  ignoredSourcesEl.value = global.ignoredSources ?? ''
  runInTrayEl.checked = Boolean(global.runInTray)
  openAtLoginEl.checked = Boolean(global.openAtLogin)
  languageEl.value = normalizeLocale(global.language)
  oauthGoogleClientIdEl.value = global.oauthGoogleClientId ?? ''
  oauthMicrosoftClientIdEl.value = global.oauthMicrosoftClientId ?? ''
  enrichmentEnabledEl.checked = global.enrichmentEnabled !== false
  cloudRangesEnabledEl.checked = global.cloudRangesEnabled !== false
  dnsblEnabledEl.checked = global.dnsblEnabled !== false
  rdapEnabledEl.checked = global.rdapEnabled !== false
  geoIpOnlineFallbackEl.checked = Boolean(global.geoIpOnlineFallback)
  maxmindLicenseKeyEl.value = ''
  maxmindLicenseKeyEl.placeholder = global.hasMaxmindLicenseKey
    ? t('settings.maxmindKeySaved')
    : t('settings.maxmindKeyPlaceholder')
  void refreshGeoLiteStatus()
}

async function refreshGeoLiteStatus(): Promise<void> {
  if (typeof window.api.geoLiteStatus !== 'function') {
    geoliteStatusEl.textContent = t('enrichment.preloadRestart')
    return
  }
  try {
    const status = await window.api.geoLiteStatus()
    geoliteStatusEl.textContent = t('settings.geoLiteStatus', {
      city: status.cityDb ? '✓' : '—',
      asn: status.asnDb ? '✓' : '—'
    })
  } catch {
    geoliteStatusEl.textContent = ''
  }
}

export function fillSettingsAccountSelect(): void {
  const accounts = state.settings?.accounts ?? []
  const options = accounts.map(
    (a) =>
      `<option value="${escapeHtml(a.id)}"${a.id === state.dialogAccountId ? ' selected' : ''}>${escapeHtml(a.label)}</option>`
  )
  options.push(
    `<option value="${NEW_ACCOUNT_VALUE}"${state.dialogAccountId == null ? ' selected' : ''}>${escapeHtml(t('settings.newAccountOption'))}</option>`
  )
  settingsAccountSelectEl.innerHTML = options.join('')
  btnDeleteAccount.disabled = state.dialogAccountId == null
}

export function applySettings(next: SettingsPublic): void {
  state.settings = next
  filterHideGoogleNoiseEl.checked = Boolean(next.global.hideGoogleNoise)
  updateAccountUi()
}

export async function loadSettings(): Promise<void> {
  applySettings(await window.api.loadSettings())
  fillGlobalForm(state.settings!.global)
  applyUiLocale(state.settings!.global.language)
  const account = activeAccount()
  if (!accountHasAuth(account)) {
    setStatus(t('status.needSettings'))
  }
}

export function showSettingsTab(which: SettingsTab): void {
  const tabs: Array<{ id: SettingsTab; btn: HTMLButtonElement; panel: HTMLElement }> = [
    { id: 'account', btn: tabBtnAccount, panel: tabAccountEl },
    { id: 'general', btn: tabBtnGeneral, panel: tabGeneralEl },
    { id: 'enrichment', btn: tabBtnEnrichment, panel: tabEnrichmentEl }
  ]
  for (const tab of tabs) {
    const active = tab.id === which
    tab.btn.classList.toggle('active', active)
    tab.btn.setAttribute('aria-selected', String(active))
    tab.panel.classList.toggle('hidden', !active)
  }
}

export function openSettings(): void {
  state.dialogAccountId = state.settings?.activeAccountId ?? null
  fillSettingsAccountSelect()
  fillAccountForm(dialogAccount())
  if (state.settings) fillGlobalForm(state.settings.global)
  showSettingsTab('account')
  settingsDialog.showModal()
  scheduleMailboxOptionsRefresh()
}

/** Refresh account/settings labels after a locale change. */
export function refreshSettingsLocale(): void {
  if (!state.settings) return
  updateAccountUi()
  fillSettingsAccountSelect()
  if (settingsDialog.open) {
    const account = dialogAccount()
    passwordHintEl.textContent = account?.hasPassword
      ? t('settings.passwordSaved')
      : t('settings.passwordHint')
  }
}

export function initSettingsUi(): void {
  btnSettings.addEventListener('click', () => openSettings())
  btnCloseSettings.addEventListener('click', () => settingsDialog.close())
  tabBtnAccount.addEventListener('click', () => showSettingsTab('account'))
  tabBtnGeneral.addEventListener('click', () => showSettingsTab('general'))
  tabBtnEnrichment.addEventListener('click', () => showSettingsTab('enrichment'))
  btnCloseInfo.addEventListener('click', () => infoDialog.close())
  btnInfoOk.addEventListener('click', () => infoDialog.close())

  btnDownloadGeolite.addEventListener('click', async () => {
    if (typeof window.api.downloadGeoLite !== 'function') {
      geoliteStatusEl.textContent = t('enrichment.preloadRestart')
      return
    }
    geoliteStatusEl.textContent = t('settings.geoLiteDownloading')
    btnDownloadGeolite.disabled = true
    try {
      // Persist key first so download uses the saved value too.
      applySettings(await window.api.saveGlobalSettings(readGlobalForm()))
      const result = await window.api.downloadGeoLite(maxmindLicenseKeyEl.value.trim())
      geoliteStatusEl.textContent = result.message
      if (result.ok) {
        state.ipLabelCache.clear()
        await refreshGeoLiteStatus()
      }
    } catch (err) {
      geoliteStatusEl.textContent = err instanceof Error ? err.message : String(err)
    } finally {
      btnDownloadGeolite.disabled = false
    }
  })

  providerEl.addEventListener('change', () => {
    applyProviderPreset(providerEl.value as ProviderPreset)
    updateAccountNamePlaceholder()
    syncAuthModeUi()
  })

  authModeEl.addEventListener('change', () => syncAuthModeUi())

  btnOauthLogin.addEventListener('click', async () => {
    if (state.busy || state.dialogAccountId == null) {
      settingsStatusEl.textContent = t('settings.saveAccountFirst')
      return
    }
    // Persist current form (provider/auth mode) before starting the browser flow.
    setBusy(true)
    try {
      applySettings(await window.api.saveAccount(readAccountForm()))
      state.dialogAccountId = state.dialogAccountId ?? state.settings?.activeAccountId ?? null
      applySettings(await window.api.oauthLogin(state.dialogAccountId!))
      fillSettingsAccountSelect()
      fillAccountForm(dialogAccount())
      settingsStatusEl.textContent = t('settings.oauthConnected')
      scheduleMailboxOptionsRefresh()
    } catch (err) {
      settingsStatusEl.textContent = err instanceof Error ? err.message : String(err)
    } finally {
      setBusy(false)
    }
  })

  btnOauthDisconnect.addEventListener('click', async () => {
    if (state.busy || state.dialogAccountId == null) return
    setBusy(true)
    try {
      applySettings(await window.api.oauthDisconnect(state.dialogAccountId))
      fillAccountForm(dialogAccount())
      settingsStatusEl.textContent = t('settings.oauthDisconnect')
    } catch (err) {
      settingsStatusEl.textContent = err instanceof Error ? err.message : String(err)
    } finally {
      setBusy(false)
    }
  })

  userEl.addEventListener('input', () => updateAccountNamePlaceholder())
  hostEl.addEventListener('input', () => updateAccountNamePlaceholder())

  settingsAccountSelectEl.addEventListener('change', () => {
    state.dialogAccountId =
      settingsAccountSelectEl.value === NEW_ACCOUNT_VALUE ? null : settingsAccountSelectEl.value
    fillSettingsAccountSelect()
    fillAccountForm(dialogAccount())
    scheduleMailboxOptionsRefresh()
  })

  btnNewAccount.addEventListener('click', () => {
    state.dialogAccountId = null
    fillSettingsAccountSelect()
    fillAccountForm(null)
    fillMailboxOptions([])
  })

  btnDeleteAccount.addEventListener('click', async () => {
    if (state.busy || state.dialogAccountId == null) return
    const account = dialogAccount()
    if (!account) return
    if (!confirm(t('settings.confirmDelete', { label: account.label }))) return
    setBusy(true)
    try {
      const wasActive = state.settings?.activeAccountId === state.dialogAccountId
      applySettings(await window.api.deleteAccount(state.dialogAccountId))
      state.dialogAccountId = state.settings?.activeAccountId ?? null
      fillSettingsAccountSelect()
      fillAccountForm(dialogAccount())
      settingsStatusEl.textContent = t('settings.accountDeleted')
      if (wasActive) {
        state.selectedReportId = null
        state.fullResult = null
        if (state.settings?.activeAccountId) {
          await switchActiveAccountFn?.(state.settings.activeAccountId)
        } else {
          applyView()
          setStatus(t('status.noAccount'))
        }
      }
    } catch (err) {
      settingsStatusEl.textContent = err instanceof Error ? err.message : String(err)
    } finally {
      setBusy(false)
    }
  })

  btnTest.addEventListener('click', async () => {
    if (state.busy) return
    setBusy(true)
    settingsStatusEl.textContent = t('settings.testing')
    try {
      const result = await window.api.testConnection(readAccountForm())
      settingsStatusEl.textContent = result.message
      setStatus(result.message, result.ok ? 'ok' : 'error')
      if (result.ok) {
        try {
          await loadMailboxOptions()
        } catch {
          // Ordnerliste ist optional nach dem Verbindungstest.
        }
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      settingsStatusEl.textContent = msg
      setStatus(msg, 'error')
    } finally {
      setBusy(false)
    }
  })

  for (const el of [mailboxEl, archiveMailboxEl]) {
    const menu = el.parentElement?.querySelector<HTMLUListElement>('[data-mailbox-menu]')
    // Keep input focus when using the list/scrollbar so the menu stays open.
    menu?.addEventListener('mousedown', (event) => event.preventDefault())
    el.addEventListener('focus', () => {
      scheduleMailboxOptionsRefresh()
      openMailboxMenu(el)
    })
    el.addEventListener('click', () => openMailboxMenu(el))
    el.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') closeMailboxMenus()
    })
  }

  archiveMailboxEl.addEventListener('input', () => syncArchiveMailboxClear())
  btnClearArchiveMailbox.addEventListener('mousedown', (event) => event.preventDefault())
  btnClearArchiveMailbox.addEventListener('click', () => {
    archiveMailboxEl.value = ''
    syncArchiveMailboxClear()
    closeMailboxMenus()
    archiveMailboxEl.focus()
  })

  btnCloseCreateMailbox.addEventListener('click', () => {
    if (!createMailboxBusy) closeCreateMailboxDialog()
  })
  btnCancelCreateMailbox.addEventListener('click', () => {
    if (!createMailboxBusy) closeCreateMailboxDialog()
  })
  btnConfirmCreateMailbox.addEventListener('click', () => {
    void confirmCreateMailbox()
  })
  createMailboxPathEl.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault()
      void confirmCreateMailbox()
    }
  })
  createMailboxDialog.addEventListener('cancel', (event) => {
    if (createMailboxBusy) {
      event.preventDefault()
      return
    }
    createMailboxTarget = null
  })

  document.addEventListener('pointerdown', (event) => {
    if (!isInsideMailboxCombo(event.target)) closeMailboxMenus()
  })

  btnClearCache.addEventListener('click', async () => {
    if (state.busy) return
    if (state.dialogAccountId == null) {
      settingsStatusEl.textContent = t('settings.saveAccountFirst')
      return
    }
    setBusy(true)
    try {
      const result = await window.api.clearCache(state.dialogAccountId)
      settingsStatusEl.textContent = result.message
      if (result.ok && state.dialogAccountId === state.settings?.activeAccountId) {
        state.fullResult = null
        applyView()
        setStatus(t('status.cacheCleared'), 'ok')
      }
    } catch (err) {
      settingsStatusEl.textContent = err instanceof Error ? err.message : String(err)
    } finally {
      setBusy(false)
    }
  })

  settingsForm.addEventListener('submit', async (event) => {
    event.preventDefault()
    if (state.busy) return
    setBusy(true)
    try {
      const accountInput = readAccountForm()
      // Always persist the edited account when one is selected (incl. display name only).
      const wantsAccountSave =
        state.dialogAccountId != null ||
        Boolean(accountInput.user || accountInput.host || accountInput.password)
      if (wantsAccountSave) {
        if (!accountInput.user || !accountInput.host) {
          showSettingsTab('account')
          throw new Error(t('settings.needUserHost'))
        }
        const before = new Set((state.settings?.accounts ?? []).map((a) => a.id))
        applySettings(await window.api.saveAccount(accountInput))
        if (state.dialogAccountId == null) {
          state.dialogAccountId =
            state.settings?.accounts.find((a) => !before.has(a.id))?.id ?? null
        }
      }
      applySettings(await window.api.saveGlobalSettings(readGlobalForm()))
      passwordEl.value = ''
      fillSettingsAccountSelect()
      fillAccountForm(dialogAccount())
      fillGlobalForm(state.settings!.global)
      applyUiLocale(state.settings!.global.language)
      settingsStatusEl.textContent = t('settings.saved')
      setStatus(t('status.settingsSaved'), 'ok')
      settingsDialog.close()
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      settingsStatusEl.textContent = msg
      setStatus(msg, 'error')
    } finally {
      setBusy(false)
    }
  })
}
