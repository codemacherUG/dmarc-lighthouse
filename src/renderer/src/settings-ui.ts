import { suggestAccountName } from '../../shared/account'
import { normalizeLocale, t, type MessageKey } from '../../shared/i18n'
import { normalizeTheme } from '../../shared/theme'
import type {
  AccountPublic,
  AccountSettingsInput,
  AuthMode,
  GlobalSettings,
  ProviderPreset,
  SendingService,
  SendingServiceStatus,
  SettingsPublic
} from '../../shared/types'
import { PROVIDER_PRESETS } from '../../shared/types'
import { applyUiLocale, setBusy, setStatus } from './chrome'
import { applyTheme } from './theme'
import {
  accountFieldEl,
  accountNameEl,
  accountSelectEl,
  archiveMailboxEl,
  authModeEl,
  autoFetchMinutesEl,
  btnAddSendingService,
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
  btnPdfDir,
  btnPdfNow,
  btnResetKnownSources,
  btnSettings,
  btnTest,
  cloudRangesEnabledEl,
  filterHideMailboxNoiseEl,
  createMailboxDialog,
  createMailboxPathEl,
  createMailboxStatusEl,
  dnsblEnabledEl,
  enrichmentEnabledEl,
  geoIpOnlineFallbackEl,
  geoliteStatusEl,
  hostEl,
  ignoredSourcesEl,
  scannerNoiseHostsEl,
  infoDialog,
  languageEl,
  themeEl,
  mailboxEl,
  mailboxListStatusEl,
  markSeenAfterFetchEl,
  maxmindLicenseKeyEl,
  notifyNewSourceEl,
  notifyOnFailEl,
  oauthActionsEl,
  oauthClientIdsEl,
  oauthGoogleClientIdEl,
  oauthGoogleFieldEl,
  oauthMicrosoftClientIdEl,
  oauthMicrosoftFieldEl,
  oauthSetupGoogleEl,
  oauthSetupMicrosoftEl,
  openAtLoginEl,
  passRateAlertThresholdEl,
  passwordEl,
  passwordFieldEl,
  passwordHintEl,
  pdfMonthlyDirEl,
  pdfMonthlyEnabledEl,
  pdfMonthlyLastEl,
  portEl,
  providerEl,
  rdapEnabledEl,
  runInTrayEl,
  secureEl,
  sendingServiceAsnEl,
  sendingServiceCidrEl,
  sendingServiceDomainEl,
  sendingServiceNoteEl,
  sendingServiceProviderEl,
  sendingServiceStatusEl,
  sendingServiceTeamEl,
  sendingServicesBodyEl,
  sendingServicesStatusEl,
  settingsAccountSelectEl,
  settingsDialog,
  settingsForm,
  settingsStatusEl,
  subjectFilterEl,
  tabAccountEl,
  tabAppearanceEl,
  tabBtnAccount,
  tabBtnAppearance,
  tabBtnEnrichment,
  tabBtnGeneral,
  tabBtnNoise,
  tabBtnSendingServices,
  tabEnrichmentEl,
  tabGeneralEl,
  tabNoiseEl,
  tabSendingServicesEl,
  userEl
} from './dom'
import { escapeHtml, formatDate } from './format'
import { state } from './state'
import { applyView } from './view'
import {
  DEFAULT_MAILBOX_NOISE_PROVIDERS,
  MAILBOX_NOISE_PROVIDERS,
  parseMailboxNoiseProviders,
  type MailboxNoiseProvider
} from '../../shared/mailbox-ip'

export const NEW_ACCOUNT_VALUE = '__new__'

type SettingsTab = 'account' | 'appearance' | 'general' | 'noise' | 'sendingServices' | 'enrichment'

function mailboxNoiseCheckbox(id: MailboxNoiseProvider): HTMLInputElement | null {
  return document.getElementById(`mailbox-noise-${id}`) as HTMLInputElement | null
}

function readMailboxNoiseProviders(): string {
  return MAILBOX_NOISE_PROVIDERS.filter((id) => mailboxNoiseCheckbox(id)?.checked).join(',')
}

function fillMailboxNoiseProviders(text: string): void {
  const enabled = parseMailboxNoiseProviders(text)
  for (const id of MAILBOX_NOISE_PROVIDERS) {
    const el = mailboxNoiseCheckbox(id)
    if (el) el.checked = enabled.has(id)
  }
}

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
  const google = provider === 'gmail'
  const microsoft = provider === 'outlook' || provider === 'microsoft'
  const oauthSupported = google || microsoft
  passwordFieldEl.classList.toggle('hidden', oauth)
  oauthActionsEl.classList.toggle('hidden', !oauth)
  oauthClientIdsEl.classList.toggle('hidden', !oauth)
  oauthGoogleFieldEl.classList.toggle('hidden', oauth && !google && microsoft)
  oauthMicrosoftFieldEl.classList.toggle('hidden', oauth && !microsoft && google)
  oauthSetupGoogleEl.classList.toggle('hidden', oauth && !google && microsoft)
  oauthSetupMicrosoftEl.classList.toggle('hidden', oauth && !microsoft && google)
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
    if (!quiet) mailboxListStatusEl.textContent = t('enrichment.preloadRestart')
    return false
  }
  const token = ++mailboxLoadToken
  if (!quiet) mailboxListStatusEl.textContent = t('settings.listingMailboxes')
  try {
    const result = await window.api.listMailboxes(readAccountForm())
    if (token !== mailboxLoadToken) return false
    if (!result.ok) {
      if (!quiet) {
        mailboxListStatusEl.textContent = result.message
        setStatus(result.message, 'error')
      }
      return false
    }
    fillMailboxOptions(result.mailboxes.map((m) => m.path))
    mailboxListStatusEl.textContent = result.message
    if (!quiet) setStatus(result.message, 'ok')
    return true
  } catch (err) {
    if (token !== mailboxLoadToken) return false
    if (!quiet) {
      const msg = err instanceof Error ? err.message : String(err)
      mailboxListStatusEl.textContent = msg
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
    theme: normalizeTheme(themeEl.value),
    oauthGoogleClientId: oauthGoogleClientIdEl.value.trim(),
    oauthMicrosoftClientId: oauthMicrosoftClientIdEl.value.trim(),
    enrichmentEnabled: enrichmentEnabledEl.checked,
    geoIpOnlineFallback: geoIpOnlineFallbackEl.checked,
    maxmindLicenseKey: maxmindLicenseKeyEl.value.trim(),
    hasMaxmindLicenseKey: Boolean(state.settings?.global.hasMaxmindLicenseKey),
    dnsblEnabled: dnsblEnabledEl.checked,
    cloudRangesEnabled: cloudRangesEnabledEl.checked,
    rdapEnabled: rdapEnabledEl.checked,
    hideMailboxNoise: filterHideMailboxNoiseEl.checked,
    mailboxNoiseProviders: readMailboxNoiseProviders(),
    scannerNoiseHosts: scannerNoiseHostsEl.value,
    pdfMonthlyEnabled: pdfMonthlyEnabledEl.checked,
    pdfMonthlyDir: pdfMonthlyDirEl.value.trim(),
    // Owned by the scheduler in the main process; sent back unchanged.
    pdfMonthlyLastRun: state.settings?.global.pdfMonthlyLastRun ?? ''
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
  mailboxListStatusEl.textContent = ''
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
  fillMailboxNoiseProviders(global.mailboxNoiseProviders ?? DEFAULT_MAILBOX_NOISE_PROVIDERS)
  scannerNoiseHostsEl.value = global.scannerNoiseHosts ?? ''
  runInTrayEl.checked = Boolean(global.runInTray)
  openAtLoginEl.checked = Boolean(global.openAtLogin)
  languageEl.value = normalizeLocale(global.language)
  themeEl.value = normalizeTheme(global.theme)
  applyTheme(normalizeTheme(global.theme))
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
  pdfMonthlyEnabledEl.checked = Boolean(global.pdfMonthlyEnabled)
  pdfMonthlyDirEl.value = global.pdfMonthlyDir ?? ''
  pdfMonthlyLastEl.textContent = global.pdfMonthlyLastRun
    ? t('settings.pdfMonthlyLast', { date: formatDate(global.pdfMonthlyLastRun) })
    : t('settings.pdfMonthlyNever')
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
  filterHideMailboxNoiseEl.checked = Boolean(next.global.hideMailboxNoise)
  updateAccountUi()
  if (state.fullResult) applyView()
}

export async function loadSettings(): Promise<void> {
  applySettings(await window.api.loadSettings())
  fillGlobalForm(state.settings!.global)
  applyUiLocale(state.settings!.global.language)
  applyTheme(state.settings!.global.theme)
  const account = activeAccount()
  if (!accountHasAuth(account)) {
    setStatus(t('status.needSettings'))
  }
}

export function showSettingsTab(which: SettingsTab): void {
  const tabs: Array<{ id: SettingsTab; btn: HTMLButtonElement; panel: HTMLElement }> = [
    { id: 'account', btn: tabBtnAccount, panel: tabAccountEl },
    { id: 'appearance', btn: tabBtnAppearance, panel: tabAppearanceEl },
    { id: 'noise', btn: tabBtnNoise, panel: tabNoiseEl },
    { id: 'sendingServices', btn: tabBtnSendingServices, panel: tabSendingServicesEl },
    { id: 'general', btn: tabBtnGeneral, panel: tabGeneralEl },
    { id: 'enrichment', btn: tabBtnEnrichment, panel: tabEnrichmentEl }
  ]
  for (const tab of tabs) {
    const active = tab.id === which
    tab.btn.classList.toggle('active', active)
    tab.btn.setAttribute('aria-selected', String(active))
    tab.panel.classList.toggle('hidden', !active)
  }
  if (which === 'sendingServices') void loadSendingServices()
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

const STATUS_KEYS: Record<SendingServiceStatus, MessageKey> = {
  known: 'sendingServices.status.known',
  unknown: 'sendingServices.status.unknown',
  investigate: 'sendingServices.status.investigate',
  retired: 'sendingServices.status.retired'
}

let sendingServices: SendingService[] = []
let nextSendingServiceCreatedHandler: ((service: SendingService) => Promise<void>) | null = null

export function setNextSendingServiceCreatedHandler(
  handler: ((service: SendingService) => Promise<void>) | null
): void {
  nextSendingServiceCreatedHandler = handler
}

async function loadSendingServices(): Promise<void> {
  try {
    sendingServices = await window.api.listSendingServices()
    renderSendingServices()
  } catch (err) {
    sendingServicesStatusEl.textContent = err instanceof Error ? err.message : String(err)
  }
}

function renderSendingServices(): void {
  sendingServicesBodyEl.innerHTML = ''
  if (sendingServices.length === 0) {
    const tr = document.createElement('tr')
    const td = document.createElement('td')
    td.colSpan = 7
    td.className = 'hint'
    td.textContent = t('sendingServices.empty')
    tr.appendChild(td)
    sendingServicesBodyEl.appendChild(tr)
    return
  }
  for (const service of sendingServices) {
    sendingServicesBodyEl.appendChild(renderSendingServiceRow(service))
  }
}

function renderSendingServiceRow(service: SendingService): HTMLTableRowElement {
  const tr = document.createElement('tr')

  const providerTd = document.createElement('td')
  providerTd.textContent = service.provider
  tr.appendChild(providerTd)

  const domainTd = document.createElement('td')
  domainTd.textContent = service.domain || '—'
  tr.appendChild(domainTd)

  const scopeTd = document.createElement('td')
  scopeTd.textContent = [service.cidr, service.asn != null ? `AS${service.asn}` : null]
    .filter(Boolean)
    .join(' · ')
  tr.appendChild(scopeTd)

  const statusTd = document.createElement('td')
  const statusSelect = document.createElement('select')
  for (const [value, key] of Object.entries(STATUS_KEYS) as Array<
    [SendingServiceStatus, MessageKey]
  >) {
    const opt = document.createElement('option')
    opt.value = value
    opt.textContent = t(key)
    if (value === service.status) opt.selected = true
    statusSelect.appendChild(opt)
  }
  statusSelect.addEventListener('change', () => {
    void saveSendingServiceEdit(service, { status: statusSelect.value as SendingServiceStatus })
  })
  statusTd.appendChild(statusSelect)
  tr.appendChild(statusTd)

  const teamTd = document.createElement('td')
  const teamInput = document.createElement('input')
  teamInput.type = 'text'
  teamInput.value = service.team ?? ''
  teamInput.addEventListener('change', () => {
    void saveSendingServiceEdit(service, { team: teamInput.value.trim() || null })
  })
  teamTd.appendChild(teamInput)
  tr.appendChild(teamTd)

  const noteTd = document.createElement('td')
  const noteInput = document.createElement('input')
  noteInput.type = 'text'
  noteInput.value = service.note ?? ''
  noteInput.addEventListener('change', () => {
    void saveSendingServiceEdit(service, { note: noteInput.value.trim() || null })
  })
  noteTd.appendChild(noteInput)
  tr.appendChild(noteTd)

  const actionsTd = document.createElement('td')
  const deleteBtn = document.createElement('button')
  deleteBtn.type = 'button'
  deleteBtn.className = 'btn secondary'
  deleteBtn.textContent = t('sendingServices.delete')
  deleteBtn.title = t('sendingServices.deleteTitle')
  deleteBtn.addEventListener('click', () => void removeSendingService(service.id))
  actionsTd.appendChild(deleteBtn)
  tr.appendChild(actionsTd)

  return tr
}

async function saveSendingServiceEdit(
  service: SendingService,
  changes: Partial<Pick<SendingService, 'status' | 'team' | 'note'>>
): Promise<void> {
  try {
    await window.api.saveSendingService({ ...service, ...changes })
    sendingServicesStatusEl.textContent = t('sendingServices.saved')
    await loadSendingServices()
  } catch (err) {
    sendingServicesStatusEl.textContent = err instanceof Error ? err.message : String(err)
  }
}

async function removeSendingService(id: string): Promise<void> {
  try {
    sendingServices = await window.api.deleteSendingService(id)
    sendingServicesStatusEl.textContent = t('sendingServices.deleted')
    renderSendingServices()
  } catch (err) {
    sendingServicesStatusEl.textContent = err instanceof Error ? err.message : String(err)
  }
}

function hasSendingServiceDraft(): boolean {
  return Boolean(
    sendingServiceProviderEl.value.trim() ||
    sendingServiceDomainEl.value.trim() ||
    sendingServiceCidrEl.value.trim() ||
    sendingServiceAsnEl.value.trim() ||
    sendingServiceTeamEl.value.trim() ||
    sendingServiceNoteEl.value.trim() ||
    sendingServiceStatusEl.value !== 'unknown'
  )
}

async function addSendingServiceFromForm(): Promise<boolean> {
  const provider = sendingServiceProviderEl.value.trim()
  if (!provider) {
    sendingServicesStatusEl.textContent = t('sendingServices.providerRequired')
    return false
  }
  const asnRaw = sendingServiceAsnEl.value.trim()
  const asn = asnRaw ? Number(asnRaw) : null
  try {
    const savedService = await window.api.saveSendingService({
      provider,
      domain: sendingServiceDomainEl.value.trim() || null,
      cidr: sendingServiceCidrEl.value.trim() || null,
      asn: asn != null && Number.isFinite(asn) ? asn : null,
      status: sendingServiceStatusEl.value as SendingServiceStatus,
      team: sendingServiceTeamEl.value.trim() || null,
      note: sendingServiceNoteEl.value.trim() || null
    })
    sendingServiceProviderEl.value = ''
    sendingServiceDomainEl.value = ''
    sendingServiceCidrEl.value = ''
    sendingServiceAsnEl.value = ''
    sendingServiceTeamEl.value = ''
    sendingServiceNoteEl.value = ''
    sendingServiceStatusEl.value = 'unknown'
    sendingServicesStatusEl.textContent = t('sendingServices.saved')
    await loadSendingServices()
    const createdHandler = nextSendingServiceCreatedHandler
    nextSendingServiceCreatedHandler = null
    await createdHandler?.(savedService)
    return true
  } catch (err) {
    sendingServicesStatusEl.textContent = err instanceof Error ? err.message : String(err)
    return false
  }
}

export function initSettingsUi(): void {
  btnSettings.addEventListener('click', () => openSettings())
  btnCloseSettings.addEventListener('click', () => settingsDialog.close())
  settingsDialog.addEventListener('close', () => {
    nextSendingServiceCreatedHandler = null
  })
  tabBtnAccount.addEventListener('click', () => showSettingsTab('account'))
  tabBtnAppearance.addEventListener('click', () => showSettingsTab('appearance'))
  tabBtnNoise.addEventListener('click', () => showSettingsTab('noise'))
  tabBtnSendingServices.addEventListener('click', () => showSettingsTab('sendingServices'))
  tabBtnGeneral.addEventListener('click', () => showSettingsTab('general'))
  tabBtnEnrichment.addEventListener('click', () => showSettingsTab('enrichment'))
  btnCloseInfo.addEventListener('click', () => infoDialog.close())
  btnInfoOk.addEventListener('click', () => infoDialog.close())

  btnAddSendingService.addEventListener('click', () => void addSendingServiceFromForm())

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

  btnPdfDir.addEventListener('click', async () => {
    try {
      const picked = await window.api.chooseReportDir()
      if (picked.ok) pdfMonthlyDirEl.value = picked.dir
    } catch (err) {
      settingsStatusEl.textContent = err instanceof Error ? err.message : String(err)
    }
  })

  btnPdfNow.addEventListener('click', async () => {
    btnPdfNow.disabled = true
    settingsStatusEl.textContent = t('settings.pdfMonthlyRunning')
    try {
      // Persist the target folder first so the run writes where the form points.
      applySettings(await window.api.saveGlobalSettings(readGlobalForm()))
      const result = await window.api.runMonthlyReport()
      settingsStatusEl.textContent = result.message
    } catch (err) {
      settingsStatusEl.textContent = err instanceof Error ? err.message : String(err)
    } finally {
      btnPdfNow.disabled = false
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
    // Persist client IDs and the account before starting the browser flow.
    setBusy(true)
    try {
      applySettings(await window.api.saveGlobalSettings(readGlobalForm()))
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

  btnResetKnownSources.addEventListener('click', async () => {
    if (state.busy) return
    if (state.dialogAccountId == null) {
      settingsStatusEl.textContent = t('settings.saveAccountFirst')
      return
    }
    setBusy(true)
    try {
      const result = await window.api.resetKnownSources(state.dialogAccountId)
      settingsStatusEl.textContent = result.message
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
      if (hasSendingServiceDraft()) {
        showSettingsTab('sendingServices')
        if (!(await addSendingServiceFromForm())) return
      }
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
      applyTheme(state.settings!.global.theme)
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
