import {
  ArcElement,
  BarElement,
  CategoryScale,
  Chart,
  DoughnutController,
  BarController,
  Legend,
  LinearScale,
  LineController,
  LineElement,
  PointElement,
  Tooltip,
  Filler
} from 'chart.js'
import { suggestAccountName } from '../../shared/account'
import {
  analyzeFromReports,
  applyDashboardFilter,
  buildDomainStats,
  mergeDomainHealth
} from '../../shared/analyze'
import { buildDemoAnalyzeResult, buildDemoSettings, DEMO_DNS_HTML } from '../../shared/demo-data'
import {
  getLocale,
  normalizeLocale,
  setLocale,
  t,
  type AppLocale,
  type MessageKey
} from '../../shared/i18n'
import type {
  AccountPublic,
  AccountSettingsInput,
  AlignmentBreakdown,
  AnalyzeProgress,
  AnalyzeResult,
  AuthMode,
  DateRangePreset,
  DomainHealth,
  ForensicReportRow,
  GlobalSettings,
  IpInfo,
  NamedBucket,
  ProviderPreset,
  ReportRow,
  SettingsPublic,
  UpdateStatusPayload
} from '../../shared/types'
import { PROVIDER_PRESETS } from '../../shared/types'

Chart.register(
  ArcElement,
  BarElement,
  CategoryScale,
  LinearScale,
  DoughnutController,
  BarController,
  LineController,
  LineElement,
  PointElement,
  Legend,
  Tooltip,
  Filler
)

const PASS = '#1f7a45'
const FAIL = '#b33a2b'
const OTHER = '#8a93a3'
const VOLUME_PASS = 'rgba(31, 122, 69, 0.85)'
const VOLUME_FAIL = 'rgba(179, 58, 43, 0.8)'
const RATE_LINE = '#1f6f8b'

const DISPOSITION_COLORS: Record<string, string> = {
  none: '#1f6f8b',
  quarantine: '#b57b12',
  reject: '#b33a2b'
}

const statusEl = document.getElementById('status') as HTMLDivElement
const progressEl = document.getElementById('progress') as HTMLProgressElement
const progressLabelEl = document.getElementById('progress-label') as HTMLSpanElement
const accountLabelEl = document.getElementById('account-label') as HTMLSpanElement
const reportsBody = document.getElementById('reports-body') as HTMLTableSectionElement
const detailEl = document.getElementById('detail') as HTMLDivElement
const tableOrgs = document.getElementById('table-orgs') as HTMLTableSectionElement
const tableIps = document.getElementById('table-ips') as HTMLTableSectionElement
const tableFrom = document.getElementById('table-from') as HTMLTableSectionElement
const dropOverlay = document.getElementById('drop-overlay') as HTMLDivElement
const filterRangeEl = document.getElementById('filter-range') as HTMLSelectElement
const filterCustomWrap = document.getElementById('filter-custom-range') as HTMLLabelElement
const filterFromEl = document.getElementById('filter-from') as HTMLInputElement
const filterToEl = document.getElementById('filter-to') as HTMLInputElement
const filterDomainEl = document.getElementById('filter-domain') as HTMLSelectElement
const filterChipsEl = document.getElementById('filter-chips') as HTMLDivElement
const accountFieldEl = document.getElementById('account-field') as HTMLLabelElement
const accountSelectEl = document.getElementById('account-select') as HTMLSelectElement
const dnsDomainEl = document.getElementById('dns-domain') as HTMLInputElement
const dnsSelectorsEl = document.getElementById('dns-selectors') as HTMLInputElement
const dnsResultEl = document.getElementById('dns-result') as HTMLDivElement
const domainAmpelEl = document.getElementById('domain-ampel') as HTMLDivElement
const ipDetailDialog = document.getElementById('ip-detail-dialog') as HTMLDialogElement
const ipDetailBody = document.getElementById('ip-detail-body') as HTMLDivElement
const btnCloseIpDetail = document.getElementById('btn-close-ip-detail') as HTMLButtonElement
const btnIpRdap = document.getElementById('btn-ip-rdap') as HTMLButtonElement
const btnIpFilter = document.getElementById('btn-ip-filter') as HTMLButtonElement

const btnSettings = document.getElementById('btn-settings') as HTMLButtonElement
const btnInfo = document.getElementById('btn-info') as HTMLButtonElement
const btnFetch = document.getElementById('btn-fetch') as HTMLButtonElement
const btnOpenFiles = document.getElementById('btn-open-files') as HTMLButtonElement
const btnExport = document.getElementById('btn-export') as HTMLButtonElement
const btnDns = document.getElementById('btn-dns') as HTMLButtonElement
const settingsDialog = document.getElementById('settings-dialog') as HTMLDialogElement
const infoDialog = document.getElementById('info-dialog') as HTMLDialogElement
const exportDialog = document.getElementById('export-dialog') as HTMLDialogElement
const createMailboxDialog = document.getElementById('create-mailbox-dialog') as HTMLDialogElement
const createMailboxPathEl = document.getElementById('create-mailbox-path') as HTMLInputElement
const createMailboxStatusEl = document.getElementById('create-mailbox-status') as HTMLParagraphElement
const btnCloseCreateMailbox = document.getElementById(
  'btn-close-create-mailbox'
) as HTMLButtonElement
const btnCancelCreateMailbox = document.getElementById(
  'btn-cancel-create-mailbox'
) as HTMLButtonElement
const btnConfirmCreateMailbox = document.getElementById(
  'btn-confirm-create-mailbox'
) as HTMLButtonElement
/** Input that opened the create-mailbox dialog (mailbox or archive). */
let createMailboxTarget: HTMLInputElement | null = null
let createMailboxBusy = false
const settingsForm = document.getElementById('settings-form') as HTMLFormElement
const btnCloseSettings = document.getElementById('btn-close-settings') as HTMLButtonElement
const btnCloseInfo = document.getElementById('btn-close-info') as HTMLButtonElement
const btnCloseExport = document.getElementById('btn-close-export') as HTMLButtonElement
const btnInfoOk = document.getElementById('btn-info-ok') as HTMLButtonElement
const btnCheckUpdate = document.getElementById('btn-check-update') as HTMLButtonElement
const btnTest = document.getElementById('btn-test') as HTMLButtonElement
const btnClearCache = document.getElementById('btn-clear-cache') as HTMLButtonElement
const btnExportCsv = document.getElementById('btn-export-csv') as HTMLButtonElement
const btnExportJson = document.getElementById('btn-export-json') as HTMLButtonElement
const passwordHintEl = document.getElementById('password-hint') as HTMLParagraphElement
const settingsStatusEl = document.getElementById('settings-status') as HTMLParagraphElement
const aboutVersionEl = document.getElementById('about-version') as HTMLSpanElement
const updateCheckStatusEl = document.getElementById('update-check-status') as HTMLParagraphElement
const updateBanner = document.getElementById('update-banner') as HTMLDivElement
const updateBannerText = document.getElementById('update-banner-text') as HTMLSpanElement
const btnUpdateInstall = document.getElementById('btn-update-install') as HTMLButtonElement
const btnUpdateDismiss = document.getElementById('btn-update-dismiss') as HTMLButtonElement

const settingsAccountSelectEl = document.getElementById(
  'settings-account-select'
) as HTMLSelectElement
const btnNewAccount = document.getElementById('btn-new-account') as HTMLButtonElement
const btnDeleteAccount = document.getElementById('btn-delete-account') as HTMLButtonElement
const tabBtnAccount = document.getElementById('tab-btn-account') as HTMLButtonElement
const tabBtnGeneral = document.getElementById('tab-btn-general') as HTMLButtonElement
const tabBtnEnrichment = document.getElementById('tab-btn-enrichment') as HTMLButtonElement
const tabAccountEl = document.getElementById('tab-account') as HTMLElement
const tabGeneralEl = document.getElementById('tab-general') as HTMLElement
const tabEnrichmentEl = document.getElementById('tab-enrichment') as HTMLElement

const providerEl = document.getElementById('provider') as HTMLSelectElement
const authModeEl = document.getElementById('authMode') as HTMLSelectElement
const accountNameEl = document.getElementById('accountName') as HTMLInputElement
const hostEl = document.getElementById('host') as HTMLInputElement
const portEl = document.getElementById('port') as HTMLInputElement
const secureEl = document.getElementById('secure') as HTMLInputElement
const userEl = document.getElementById('user') as HTMLInputElement
const passwordEl = document.getElementById('password') as HTMLInputElement
const passwordFieldEl = document.getElementById('password-field') as HTMLElement
const oauthActionsEl = document.getElementById('oauth-actions') as HTMLElement
const oauthHintEl = document.getElementById('oauth-hint') as HTMLElement
const btnOauthLogin = document.getElementById('btn-oauth-login') as HTMLButtonElement
const btnOauthDisconnect = document.getElementById('btn-oauth-disconnect') as HTMLButtonElement
const mailboxEl = document.getElementById('mailbox') as HTMLInputElement
const archiveMailboxEl = document.getElementById('archiveMailbox') as HTMLInputElement
const btnClearArchiveMailbox = document.getElementById(
  'btn-clear-archive-mailbox'
) as HTMLButtonElement
const subjectFilterEl = document.getElementById('subjectFilter') as HTMLInputElement
const markSeenAfterFetchEl = document.getElementById('markSeenAfterFetch') as HTMLInputElement
const autoFetchMinutesEl = document.getElementById('autoFetchMinutes') as HTMLInputElement
const runInTrayEl = document.getElementById('runInTray') as HTMLInputElement
const openAtLoginEl = document.getElementById('openAtLogin') as HTMLInputElement
const notifyOnFailEl = document.getElementById('notifyOnFail') as HTMLInputElement
const notifyNewSourceEl = document.getElementById('notifyNewSource') as HTMLInputElement
const passRateAlertThresholdEl = document.getElementById(
  'passRateAlertThreshold'
) as HTMLInputElement
const ignoredSourcesEl = document.getElementById('ignoredSources') as HTMLTextAreaElement
const languageEl = document.getElementById('language') as HTMLSelectElement
const oauthGoogleClientIdEl = document.getElementById('oauthGoogleClientId') as HTMLInputElement
const oauthMicrosoftClientIdEl = document.getElementById(
  'oauthMicrosoftClientId'
) as HTMLInputElement
const enrichmentEnabledEl = document.getElementById('enrichmentEnabled') as HTMLInputElement
const cloudRangesEnabledEl = document.getElementById('cloudRangesEnabled') as HTMLInputElement
const dnsblEnabledEl = document.getElementById('dnsblEnabled') as HTMLInputElement
const rdapEnabledEl = document.getElementById('rdapEnabled') as HTMLInputElement
const geoIpOnlineFallbackEl = document.getElementById('geoIpOnlineFallback') as HTMLInputElement
const maxmindLicenseKeyEl = document.getElementById('maxmindLicenseKey') as HTMLInputElement
const btnDownloadGeolite = document.getElementById('btn-download-geolite') as HTMLButtonElement
const geoliteStatusEl = document.getElementById('geolite-status') as HTMLSpanElement
const forensicBody = document.getElementById('forensic-body') as HTMLTableSectionElement

const NEW_ACCOUNT_VALUE = '__new__'

let selectedReportId: string | null = null
let busy = false
let settings: SettingsPublic | null = null
/** Account currently edited in the settings dialog (null = new account). */
let dialogAccountId: string | null = null
let fullResult: AnalyzeResult | null = null
let viewResult: AnalyzeResult | null = null
/** Drill-down filters set by clicking rows in the aggregate tables. */
const drill: { org?: string; sourceIp?: string; headerFrom?: string } = {}
const ipLabelCache = new Map<string, IpInfo>()
let selectedDetailIp: string | null = null
let domainHealthCache: DomainHealth[] = []
let domainHealthToken = 0

const chartDmarc = createDoughnut('chart-dmarc')
const chartSpf = createDoughnut('chart-spf')
const chartDkim = createDoughnut('chart-dkim')
const chartDisposition = new Chart(
  document.getElementById('chart-disposition') as HTMLCanvasElement,
  {
    type: 'doughnut',
    data: {
      labels: [] as string[],
      datasets: [{ data: [] as number[], backgroundColor: [] as string[], borderWidth: 0 }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: 'bottom' } }
    }
  }
)
const chartVolume = new Chart(document.getElementById('chart-volume') as HTMLCanvasElement, {
  data: {
    labels: [] as string[],
    datasets: [
      {
        type: 'bar',
        label: 'Pass',
        data: [] as number[],
        backgroundColor: VOLUME_PASS,
        stack: 'v',
        yAxisID: 'y'
      },
      {
        type: 'bar',
        label: 'Fail',
        data: [] as number[],
        backgroundColor: VOLUME_FAIL,
        stack: 'v',
        yAxisID: 'y'
      },
      {
        type: 'line',
        label: 'Pass-Rate %',
        data: [] as number[],
        borderColor: RATE_LINE,
        backgroundColor: 'rgba(31, 111, 139, 0.12)',
        tension: 0.25,
        fill: false,
        yAxisID: 'y1',
        pointRadius: 2,
        borderWidth: 2
      }
    ]
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { mode: 'index', intersect: false },
    scales: {
      x: { stacked: true, grid: { display: false } },
      y: { stacked: true, beginAtZero: true, position: 'left' },
      y1: {
        beginAtZero: true,
        max: 100,
        position: 'right',
        grid: { drawOnChartArea: false },
        ticks: { callback: (v) => `${v}%` }
      }
    },
    plugins: {
      legend: { position: 'bottom' }
    }
  }
})

function createDoughnut(id: string): Chart<'doughnut'> {
  return new Chart(document.getElementById(id) as HTMLCanvasElement, {
    type: 'doughnut',
    data: {
      labels: ['Pass', 'Fail', 'Sonstige'],
      datasets: [
        {
          data: [0, 0, 0],
          backgroundColor: [PASS, FAIL, OTHER],
          borderWidth: 0
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'bottom' }
      }
    }
  })
}

function setStatus(message: string, kind: 'ok' | 'error' | '' = ''): void {
  statusEl.textContent = message
  statusEl.classList.remove('ok', 'error')
  if (kind) statusEl.classList.add(kind)
}

function showUpdateBanner(text: string, showInstall: boolean): void {
  updateBannerText.textContent = text
  updateBanner.classList.remove('hidden', 'error', 'ready')
  if (showInstall) updateBanner.classList.add('ready')
  btnUpdateInstall.classList.toggle('hidden', !showInstall)
}

function hideUpdateBanner(): void {
  updateBanner.classList.add('hidden')
  btnUpdateInstall.classList.add('hidden')
}

function applyUpdateStatus(payload: UpdateStatusPayload): void {
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

function applyDomI18n(): void {
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

function applyUiLocale(locale: AppLocale): void {
  setLocale(locale)
  document.documentElement.lang = locale
  applyDomI18n()

  const doughnutLabels = [t('chart.pass'), t('chart.fail'), t('chart.other')]
  for (const chart of [chartDmarc, chartSpf, chartDkim]) {
    chart.data.labels = doughnutLabels
    chart.update()
  }
  chartVolume.data.datasets[0].label = t('chart.pass')
  chartVolume.data.datasets[1].label = t('chart.fail')
  chartVolume.data.datasets[2].label = t('chart.passRate')
  chartVolume.update()

  if (settings) {
    updateAccountUi()
    fillSettingsAccountSelect()
    if (settingsDialog.open) {
      const account = dialogAccount()
      passwordHintEl.textContent = account?.hasPassword
        ? t('settings.passwordSaved')
        : t('settings.passwordHint')
    }
  }

  if (fullResult) {
    showResult(fullResult)
  } else {
    applyView()
  }
}

function setBusy(next: boolean): void {
  busy = next
  btnFetch.disabled = next
  btnSettings.disabled = next
  btnTest.disabled = next
  btnOpenFiles.disabled = next
  btnDns.disabled = next
  accountSelectEl.disabled = next
}

function activeAccount(): AccountPublic | null {
  if (!settings) return null
  return settings.accounts.find((a) => a.id === settings?.activeAccountId) ?? null
}

function dialogAccount(): AccountPublic | null {
  if (!settings || dialogAccountId == null) return null
  return settings.accounts.find((a) => a.id === dialogAccountId) ?? null
}

function updateAccountNamePlaceholder(): void {
  accountNameEl.placeholder = suggestAccountName(userEl.value, hostEl.value)
}

function accountHasAuth(account: AccountPublic | null | undefined): boolean {
  return Boolean(account && account.user && (account.hasPassword || account.hasOAuth))
}

function syncAuthModeUi(): void {
  const oauth = authModeEl.value === 'oauth'
  const provider = providerEl.value
  const oauthSupported = provider === 'gmail' || provider === 'outlook' || provider === 'microsoft'
  passwordFieldEl.classList.toggle('hidden', oauth)
  oauthActionsEl.classList.toggle('hidden', !oauth)
  oauthHintEl.classList.toggle('hidden', !oauth)
  btnOauthLogin.disabled = !oauth || !oauthSupported || dialogAccountId == null
  btnOauthDisconnect.disabled = !oauth || dialogAccountId == null || !dialogAccount()?.hasOAuth
  if (oauth && !oauthSupported) {
    passwordHintEl.textContent = t('oauth.providerUnsupported')
  }
}

function readAccountForm(): AccountSettingsInput {
  return {
    id: dialogAccountId,
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

/** Full IMAP folder list for the custom picker (never filtered by the input value). */
let mailboxPaths: string[] = []

function fillMailboxOptions(paths: string[]): void {
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
  const el = target instanceof Element ? target : target instanceof Node ? target.parentElement : null
  return Boolean(el?.closest('.mailbox-combo'))
}

let mailboxLoadToken = 0

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

let mailboxRefreshTimer: ReturnType<typeof setTimeout> | null = null

function scheduleMailboxOptionsRefresh(): void {
  if (mailboxRefreshTimer) clearTimeout(mailboxRefreshTimer)
  mailboxRefreshTimer = setTimeout(() => {
    mailboxRefreshTimer = null
    void loadMailboxOptions({ quiet: true })
  }, 150)
}

function readGlobalForm(): GlobalSettings {
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
    dnsblEnabled: dnsblEnabledEl.checked,
    cloudRangesEnabled: cloudRangesEnabledEl.checked,
    rdapEnabled: rdapEnabledEl.checked
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

function formatDate(iso: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleDateString(getLocale() === 'de' ? 'de-DE' : 'en-US')
}

function formatRange(begin: string | null, end: string | null): string {
  return `${formatDate(begin)} – ${formatDate(end)}`
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
}

function updateAccountUi(): void {
  const account = activeAccount()
  accountLabelEl.textContent = account ? account.label : t('app.noCredentials')

  const accounts = settings?.accounts ?? []
  accountFieldEl.classList.toggle('hidden', accounts.length <= 1)
  accountSelectEl.innerHTML = accounts
    .map(
      (a) =>
        `<option value="${escapeHtml(a.id)}"${a.id === settings?.activeAccountId ? ' selected' : ''}>${escapeHtml(a.label)}</option>`
    )
    .join('')
}

function updateSummary(result: AnalyzeResult | null): void {
  const map: Record<string, string> = {
    reportCount: result ? String(result.aggregate.reportCount) : '—',
    total: result ? String(result.aggregate.total) : '—',
    passing: result ? String(result.aggregate.passing) : '—',
    failing: result ? String(result.aggregate.failing) : '—',
    passRate: result ? `${result.aggregate.passRate.toFixed(1)}%` : '—',
    range: result ? formatRange(result.aggregate.dateBegin, result.aggregate.dateEnd) : '—'
  }
  for (const [key, value] of Object.entries(map)) {
    const el = document.querySelector<HTMLElement>(`[data-key="${key}"]`)
    if (el) el.textContent = value
  }
}

function setAlignmentChart(chart: Chart<'doughnut'>, data: AlignmentBreakdown): void {
  chart.data.datasets[0].data = [data.pass, data.fail, data.other]
  chart.update()
}

function setDispositionChart(buckets: NamedBucket[]): void {
  chartDisposition.data.labels = buckets.map((b) => b.name)
  chartDisposition.data.datasets[0].data = buckets.map((b) => b.count)
  ;(chartDisposition.data.datasets[0].backgroundColor as string[]) = buckets.map(
    (b) => DISPOSITION_COLORS[b.name.toLowerCase()] ?? OTHER
  )
  chartDisposition.update()
}

/** Known ESP/cloud label, else ASN org (ISP / network). */
function resolveProviderLabel(
  info?: IpInfo | null,
  fallbackProvider?: string | null
): string | null {
  return fallbackProvider || info?.provider || info?.cloudProvider || info?.asOrg || null
}

function formatIpMetaHtml(
  ip: string,
  fallbackProvider?: string | null,
  fallbackPtr?: string | null
): string {
  const meta = ipLabelCache.get(ip)
  const provider = resolveProviderLabel(meta, fallbackProvider)
  const ptr = fallbackPtr ?? meta?.ptr
  const bits: string[] = []
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

function formatIpCellHtml(
  ip: string,
  fallbackProvider?: string | null,
  fallbackPtr?: string | null
): string {
  return `<span class="ip-cell">
    <span class="ip-cell-head mono">
      <span>${escapeHtml(ip)}</span><button type="button" class="ip-detail-btn" data-ip-detail="${escapeHtml(ip)}" title="${escapeHtml(t('ipDetail.openHint'))}" aria-label="${escapeHtml(t('ipDetail.openHint'))}">i</button>
    </span>
    ${formatIpMetaHtml(ip, fallbackProvider, fallbackPtr)}
  </span>`
}

function renderBucketTable(
  tbody: HTMLTableSectionElement,
  rows: NamedBucket[],
  options: {
    withIpMeta?: boolean
    onRowClick?: (name: string) => void
  } = {}
): void {
  if (!rows.length) {
    tbody.innerHTML = `<tr class="empty"><td colspan="3">${escapeHtml(t('table.noData'))}</td></tr>`
    return
  }
  tbody.innerHTML = rows
    .map((r) => {
      const nameHtml = options.withIpMeta
        ? formatIpCellHtml(r.name, r.provider, r.label)
        : `<span class="mono">${escapeHtml(r.name)}</span>`
      return `
      <tr data-name="${escapeHtml(r.name)}"${options.onRowClick ? ` title="${escapeHtml(t('filter.clickToFilter'))}"` : ''}>
        <td>${nameHtml}</td>
        <td>${r.count}</td>
        <td>
          <span class="rate-bar"><span style="width:${Math.min(100, r.passRate)}%"></span></span>
          ${r.passRate.toFixed(1)}%
        </td>
      </tr>`
    })
    .join('')

  if (options.onRowClick) {
    for (const tr of tbody.querySelectorAll<HTMLTableRowElement>('tr[data-name]')) {
      tr.addEventListener('click', (ev) => {
        const target = ev.target as HTMLElement
        if (target.closest('[data-ip-detail]')) return
        options.onRowClick?.(tr.dataset.name ?? '')
      })
    }
  }
  bindIpDetailButtons(tbody)
}

function bindIpDetailButtons(root: ParentNode): void {
  for (const btn of root.querySelectorAll<HTMLButtonElement>('[data-ip-detail]')) {
    btn.addEventListener('click', (ev) => {
      ev.stopPropagation()
      openIpDetail(btn.dataset.ipDetail ?? '')
    })
  }
}

function renderFilterChips(): void {
  const chips: Array<{ key: keyof typeof drill; label: string; value: string }> = []
  if (drill.org) chips.push({ key: 'org', label: t('table.org'), value: drill.org })
  if (drill.sourceIp) chips.push({ key: 'sourceIp', label: t('detail.ip'), value: drill.sourceIp })
  if (drill.headerFrom)
    chips.push({ key: 'headerFrom', label: t('detail.from'), value: drill.headerFrom })

  filterChipsEl.classList.toggle('hidden', chips.length === 0)
  filterChipsEl.innerHTML = chips
    .map(
      (c) => `
      <span class="chip">
        <span class="chip-label">${c.label}:</span>
        <span class="mono">${escapeHtml(c.value)}</span>
        <button type="button" class="chip-remove" data-chip="${c.key}" aria-label="${escapeHtml(t('filter.removeChip'))}">✕</button>
      </span>`
    )
    .join('')

  for (const btn of filterChipsEl.querySelectorAll<HTMLButtonElement>('.chip-remove')) {
    btn.addEventListener('click', () => {
      const key = btn.dataset.chip as keyof typeof drill
      delete drill[key]
      applyView()
    })
  }
}

function setDrillFilter(key: keyof typeof drill, value: string): void {
  if (!value) return
  if (drill[key] === value) delete drill[key]
  else drill[key] = value
  applyView()
}

function renderDomainAmpel(rows: DomainHealth[]): void {
  if (!rows.length) {
    domainAmpelEl.innerHTML = `<p class="muted">${escapeHtml(t('health.empty'))}</p>`
    return
  }
  domainAmpelEl.innerHTML = rows
    .map((h) => {
      const statusLabel = t(`health.status.${h.status}` as MessageKey)
      const policy =
        h.dmarcPolicy != null ? escapeHtml(t('health.policy', { policy: h.dmarcPolicy })) : '—'
      const reasons = h.reasons.map((key) => t(key as MessageKey)).join(' · ')
      return `
      <button type="button" class="ampel-card ${h.status}" data-domain="${escapeHtml(h.domain)}" title="${escapeHtml(statusLabel)}">
        <div class="ampel-domain">${escapeHtml(h.domain)}</div>
        <div class="ampel-meta">
          <span>${escapeHtml(statusLabel)}</span>
          <span>${escapeHtml(t('health.passRate', { rate: h.passRate.toFixed(1) }))}</span>
          <span>${escapeHtml(t('health.msgs', { count: String(h.total) }))}</span>
          <span>${policy}</span>
        </div>
        ${reasons ? `<div class="ampel-reasons">${escapeHtml(reasons)}</div>` : ''}
      </button>`
    })
    .join('')

  for (const btn of domainAmpelEl.querySelectorAll<HTMLButtonElement>('[data-domain]')) {
    btn.addEventListener('click', () => {
      const domain = btn.dataset.domain ?? ''
      if (!domain) return
      selectDomainFilter(domain)
      applyView()
    })
  }
}

/** Select a domain option case-insensitively (Ampel domains are lowercased). */
function selectDomainFilter(domain: string): void {
  const wanted = domain.trim().toLowerCase()
  const match = [...filterDomainEl.options].find((o) => o.value.toLowerCase() === wanted)
  filterDomainEl.value = match?.value ?? domain
}

function domainHealthFallback(reports: ReportRow[]): DomainHealth[] {
  return buildDomainStats(reports).map((stats) => mergeDomainHealth(stats, null))
}

async function refreshDomainHealth(result: AnalyzeResult | null): Promise<void> {
  const token = ++domainHealthToken
  if (!domainAmpelEl) return
  if (!result || result.reports.length === 0) {
    domainHealthCache = []
    renderDomainAmpel([])
    return
  }
  domainAmpelEl.innerHTML = `<p class="muted">${escapeHtml(t('health.loading'))}</p>`
  try {
    let health: DomainHealth[]
    if (typeof window.api.healthBatch === 'function') {
      health = await window.api.healthBatch(result.reports)
    } else {
      // Preload not yet reloaded — still show Ampel from local stats.
      health = domainHealthFallback(result.reports)
    }
    if (token !== domainHealthToken) return
    domainHealthCache = health
    renderDomainAmpel(health)
  } catch {
    if (token !== domainHealthToken) return
    domainHealthCache = domainHealthFallback(result.reports)
    renderDomainAmpel(domainHealthCache)
  }
}

function renderIpDetailBody(ip: string, rdapSummary?: string | null, rdapError?: string): void {
  const info = ipLabelCache.get(ip)
  const provider = info?.provider || info?.asOrg || null
  const geo =
    [info?.countryCode, info?.country, info?.city].filter(Boolean).join(' · ') || t('ipDetail.none')
  const asn =
    info?.asn != null ? `AS${info.asn}${info.asOrg ? ` (${info.asOrg})` : ''}` : t('ipDetail.none')
  const dnsbl = info?.dnsblHits?.length ? info.dnsblHits.join(', ') : t('ipDetail.none')
  const rdapText = rdapError || rdapSummary || t('ipDetail.none')
  ipDetailBody.innerHTML = `
    <dl>
      <dt>IP</dt><dd class="mono">${escapeHtml(ip)}</dd>
      <dt>${escapeHtml(t('ipDetail.ptr'))}</dt><dd>${escapeHtml(info?.ptr ?? t('ipDetail.none'))}</dd>
      <dt>${escapeHtml(t('ipDetail.provider'))}</dt><dd>${escapeHtml(provider ?? t('ipDetail.none'))}</dd>
      <dt>${escapeHtml(t('ipDetail.cloud'))}</dt><dd>${escapeHtml(info?.cloudProvider ?? t('ipDetail.none'))}</dd>
      <dt>${escapeHtml(t('ipDetail.geo'))}</dt><dd>${escapeHtml(geo)}</dd>
      <dt>${escapeHtml(t('ipDetail.asn'))}</dt><dd>${escapeHtml(asn)}</dd>
      <dt>${escapeHtml(t('ipDetail.dnsbl'))}</dt><dd>${escapeHtml(dnsbl)}</dd>
      <dt>${escapeHtml(t('ipDetail.rdap'))}</dt><dd id="ip-detail-rdap">${escapeHtml(rdapText)}</dd>
    </dl>`
}

function openIpDetail(ip: string): void {
  if (!ip) return
  selectedDetailIp = ip
  renderIpDetailBody(ip)
  ipDetailDialog.showModal()
}

function renderDashboard(result: AnalyzeResult | null): void {
  if (!result) {
    setAlignmentChart(chartDmarc, { pass: 0, fail: 0, other: 0 })
    setAlignmentChart(chartSpf, { pass: 0, fail: 0, other: 0 })
    setAlignmentChart(chartDkim, { pass: 0, fail: 0, other: 0 })
    setDispositionChart([])
    chartVolume.data.labels = []
    chartVolume.data.datasets[0].data = []
    chartVolume.data.datasets[1].data = []
    chartVolume.data.datasets[2].data = []
    chartVolume.update()
    renderBucketTable(tableOrgs, [])
    renderBucketTable(tableIps, [])
    renderBucketTable(tableFrom, [])
    void refreshDomainHealth(null)
    return
  }

  const d = result.dashboard
  setAlignmentChart(chartDmarc, d.dmarc)
  setAlignmentChart(chartSpf, d.spf)
  setAlignmentChart(chartDkim, d.dkim)
  setDispositionChart(d.dispositions)

  chartVolume.data.labels = d.volumeByDay.map((p) => p.date)
  chartVolume.data.datasets[0].data = d.volumeByDay.map((p) => p.passing)
  chartVolume.data.datasets[1].data = d.volumeByDay.map((p) => p.failing)
  chartVolume.data.datasets[2].data = d.volumeByDay.map((p) => p.passRate)
  chartVolume.update()

  renderBucketTable(tableOrgs, d.byOrg, {
    onRowClick: (name) => setDrillFilter('org', name)
  })
  renderBucketTable(tableIps, d.bySourceIp, {
    withIpMeta: true,
    onRowClick: (name) => setDrillFilter('sourceIp', name)
  })
  renderBucketTable(tableFrom, d.byHeaderFrom, {
    onRowClick: (name) => setDrillFilter('headerFrom', name)
  })

  void enrichIpLabels(d.bySourceIp.map((r) => r.name))
  // Ampel always reflects the unfiltered account data so domains stay clickable.
  void refreshDomainHealth(fullResult)
}

async function enrichIpLabels(ips: string[]): Promise<void> {
  const missing = ips.filter((ip) => !ipLabelCache.has(ip)).slice(0, 40)
  if (!missing.length) return
  try {
    const infos = await window.api.resolveIps(missing)
    for (const info of infos) {
      ipLabelCache.set(info.ip, info)
    }
    if (viewResult) {
      renderBucketTable(tableIps, viewResult.dashboard.bySourceIp, {
        withIpMeta: true,
        onRowClick: (name) => setDrillFilter('sourceIp', name)
      })
    }
    // Refresh open record details so geo/ASN/DNSBL appear once enrichment lands.
    if (selectedReportId && viewResult) {
      const selected =
        viewResult.reports.find((r) => r.reportId === selectedReportId) ?? null
      if (selected) renderDetail(selected)
    }
  } catch {
    // Enrichment ist optional.
  }
}

function renderDetail(report: ReportRow | null): void {
  if (!report) {
    detailEl.innerHTML = `<p class="muted">${escapeHtml(t('detail.pick'))}</p>`
    return
  }

  const rows = report.records
    .map((r) => {
      const reasons =
        r.reasons?.length > 0
          ? r.reasons
              .map((x) => escapeHtml([x.type, x.comment].filter(Boolean).join(': ')))
              .join('<br />')
          : '—'
      return `
      <tr>
        <td>${formatIpCellHtml(r.sourceIp)}</td>
        <td>${r.count}</td>
        <td>${escapeHtml(r.disposition ?? '—')}</td>
        <td class="${r.dkimResult === 'pass' ? 'pass' : 'fail'}">${escapeHtml(r.dkimResult ?? '—')}</td>
        <td class="${r.spfResult === 'pass' ? 'pass' : 'fail'}">${escapeHtml(r.spfResult ?? '—')}</td>
        <td class="${r.passesDmarc ? 'pass' : 'fail'}">${r.passesDmarc ? 'pass' : 'fail'}</td>
        <td>${escapeHtml(r.headerFrom ?? '—')}</td>
        <td class="reasons">${reasons}</td>
      </tr>`
    })
    .join('')

  detailEl.innerHTML = `
    <h3>${escapeHtml(report.orgName)} → ${escapeHtml(report.domain)}</h3>
    <div class="meta">
      ID: <span class="mono">${escapeHtml(report.reportId)}</span><br />
      ${escapeHtml(t('detail.period'))}: ${escapeHtml(formatRange(report.dateBegin, report.dateEnd))}<br />
      ${escapeHtml(t('detail.policy'))}: ${escapeHtml(report.policyP ?? '—')} ·
      ${report.passing}/${report.total} pass (${report.passRate.toFixed(1)}%)
    </div>
    <table>
      <thead>
        <tr>
          <th>${escapeHtml(t('detail.ip'))}</th>
          <th>${escapeHtml(t('detail.count'))}</th>
          <th>${escapeHtml(t('detail.disp'))}</th>
          <th>${escapeHtml(t('detail.dkim'))}</th>
          <th>${escapeHtml(t('detail.spf'))}</th>
          <th>${escapeHtml(t('detail.dmarc'))}</th>
          <th>${escapeHtml(t('detail.from'))}</th>
          <th>${escapeHtml(t('detail.reasons'))}</th>
        </tr>
      </thead>
      <tbody>${rows || `<tr><td colspan="8">${escapeHtml(t('detail.noRecords'))}</td></tr>`}</tbody>
    </table>
  `
  bindIpDetailButtons(detailEl)
  void enrichIpLabels(report.records.map((r) => r.sourceIp).filter(Boolean))
}

function renderForensic(result: AnalyzeResult | null): void {
  const rows = result?.forensicReports ?? []
  if (rows.length === 0) {
    forensicBody.innerHTML = `<tr class="empty"><td colspan="7">${escapeHtml(t('table.forensicEmpty'))}</td></tr>`
    return
  }
  forensicBody.innerHTML = rows
    .map(
      (r: ForensicReportRow) => `
      <tr>
        <td>${escapeHtml(r.arrivalDate ? r.arrivalDate.slice(0, 19).replace('T', ' ') : '—')}</td>
        <td>${escapeHtml(r.reportedDomain ?? '—')}</td>
        <td class="mono">${escapeHtml(r.sourceIp ?? '—')}</td>
        <td>${escapeHtml(r.authFailure ?? '—')}</td>
        <td>${escapeHtml(r.envelopeFrom ?? '—')}</td>
        <td>${escapeHtml(r.headerFrom ?? '—')}</td>
        <td>${escapeHtml(r.feedbackType ?? '—')}</td>
      </tr>`
    )
    .join('')
}

function renderReports(result: AnalyzeResult | null): void {
  reportsBody.innerHTML = ''
  if (!result || result.reports.length === 0) {
    reportsBody.innerHTML = `<tr class="empty"><td colspan="8">${escapeHtml(t('table.noReports'))}</td></tr>`
    renderDetail(null)
    return
  }

  for (const report of result.reports) {
    const tr = document.createElement('tr')
    tr.dataset.reportId = report.reportId
    if (report.reportId === selectedReportId) tr.classList.add('selected')
    tr.innerHTML = `
      <td>${escapeHtml(report.orgName)}</td>
      <td>${escapeHtml(report.domain)}</td>
      <td>${escapeHtml(formatRange(report.dateBegin, report.dateEnd))}</td>
      <td>${report.total}</td>
      <td class="pass">${report.passing}</td>
      <td class="fail">${report.failing}</td>
      <td>${report.passRate.toFixed(1)}%</td>
      <td>${escapeHtml(report.policyP ?? '—')}</td>
    `
    tr.addEventListener('click', () => {
      selectedReportId = report.reportId
      for (const row of reportsBody.querySelectorAll('tr')) row.classList.remove('selected')
      tr.classList.add('selected')
      renderDetail(report)
    })
    reportsBody.appendChild(tr)
  }

  const selected =
    result.reports.find((r) => r.reportId === selectedReportId) ?? result.reports[0] ?? null
  selectedReportId = selected?.reportId ?? null
  if (selected) {
    const row = reportsBody.querySelector(`tr[data-report-id="${CSS.escape(selected.reportId)}"]`)
    row?.classList.add('selected')
  }
  renderDetail(selected)
}

function fillDomainFilter(result: AnalyzeResult | null): void {
  const current = filterDomainEl.value
  const domains = result?.aggregate.domains ?? []
  filterDomainEl.innerHTML =
    `<option value="">${escapeHtml(t('filter.allDomains'))}</option>` +
    domains.map((d) => `<option value="${escapeHtml(d)}">${escapeHtml(d)}</option>`).join('')
  if (domains.includes(current)) filterDomainEl.value = current
  if (domains.length === 1 && !dnsDomainEl.value) {
    dnsDomainEl.value = domains[0]
  }
}

function applyView(): void {
  renderFilterChips()
  if (!fullResult) {
    viewResult = null
    updateSummary(null)
    renderDashboard(null)
    renderReports(null)
    renderForensic(null)
    btnExport.disabled = true
    return
  }

  viewResult = applyDashboardFilter(fullResult, {
    range: filterRangeEl.value as DateRangePreset,
    from: filterFromEl.value || undefined,
    to: filterToEl.value || undefined,
    domain: filterDomainEl.value,
    org: drill.org,
    sourceIp: drill.sourceIp,
    headerFrom: drill.headerFrom
  })
  updateSummary(viewResult)
  renderDashboard(viewResult)
  renderReports(viewResult)
  renderForensic(viewResult)
  btnExport.disabled =
    viewResult.reports.length === 0 && (viewResult.forensicReports?.length ?? 0) === 0
}

function showResult(result: AnalyzeResult, statusMessage?: string): void {
  fullResult = result
  fillDomainFilter(result)
  applyView()
  if (statusMessage) {
    setStatus(statusMessage, 'ok')
  } else {
    const skippedNote = result.skipped ? t('status.skippedPart', { count: result.skipped }) : ''
    const newNote =
      result.newReports != null ? t('status.newPart', { count: result.newReports }) : ''
    const cacheNote = result.fromCache ? t('status.cachePart') : ''
    const sourceNote = result.newSourceIps?.length
      ? t('status.sourcePart', { count: result.newSourceIps.length })
      : ''
    setStatus(
      t('status.result', {
        reports: result.aggregate.reportCount,
        newNote,
        cacheNote,
        messages: result.aggregate.total,
        skippedNote,
        sourceNote
      }),
      'ok'
    )
  }
}

function applyProgress(progress: AnalyzeProgress): void {
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

function fillAccountForm(account: AccountPublic | null): void {
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

function fillGlobalForm(global: GlobalSettings): void {
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
  maxmindLicenseKeyEl.value = global.maxmindLicenseKey ?? ''
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

function fillSettingsAccountSelect(): void {
  const accounts = settings?.accounts ?? []
  const options = accounts.map(
    (a) =>
      `<option value="${escapeHtml(a.id)}"${a.id === dialogAccountId ? ' selected' : ''}>${escapeHtml(a.label)}</option>`
  )
  options.push(
    `<option value="${NEW_ACCOUNT_VALUE}"${dialogAccountId == null ? ' selected' : ''}>${escapeHtml(t('settings.newAccountOption'))}</option>`
  )
  settingsAccountSelectEl.innerHTML = options.join('')
  btnDeleteAccount.disabled = dialogAccountId == null
}

function applySettings(next: SettingsPublic): void {
  settings = next
  updateAccountUi()
}

async function loadSettings(): Promise<void> {
  applySettings(await window.api.loadSettings())
  fillGlobalForm(settings!.global)
  applyUiLocale(settings!.global.language)
  const account = activeAccount()
  if (!accountHasAuth(account)) {
    setStatus(t('status.needSettings'))
  }
}

type SettingsTab = 'account' | 'general' | 'enrichment'

function showSettingsTab(which: SettingsTab): void {
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

function openSettings(): void {
  dialogAccountId = settings?.activeAccountId ?? null
  fillSettingsAccountSelect()
  fillAccountForm(dialogAccount())
  if (settings) fillGlobalForm(settings.global)
  showSettingsTab('account')
  settingsDialog.showModal()
  scheduleMailboxOptionsRefresh()
}

async function switchActiveAccount(id: string): Promise<void> {
  applySettings(await window.api.setActiveAccount(id))
  selectedReportId = null
  Object.keys(drill).forEach((k) => delete drill[k as keyof typeof drill])
  fullResult = null
  const cached = await window.api.loadCache(id)
  if (cached && cached.reports.length > 0) {
    showResult(cached, t('status.cached', { count: cached.aggregate.reportCount }))
  } else {
    applyView()
    setStatus(t('status.noCache'))
  }
}

btnSettings.addEventListener('click', () => openSettings())
btnCloseSettings.addEventListener('click', () => settingsDialog.close())
tabBtnAccount.addEventListener('click', () => showSettingsTab('account'))
tabBtnGeneral.addEventListener('click', () => showSettingsTab('general'))
tabBtnEnrichment.addEventListener('click', () => showSettingsTab('enrichment'))
btnCloseIpDetail.addEventListener('click', () => ipDetailDialog.close())
btnIpFilter.addEventListener('click', () => {
  if (!selectedDetailIp) return
  ipDetailDialog.close()
  setDrillFilter('sourceIp', selectedDetailIp)
})
btnIpRdap.addEventListener('click', async () => {
  if (!selectedDetailIp) return
  const rdapEl = document.getElementById('ip-detail-rdap')
  if (rdapEl) rdapEl.textContent = t('ipDetail.loadingRdap')
  try {
    const info = await window.api.lookupRdap(selectedDetailIp)
    renderIpDetailBody(selectedDetailIp, info.rawSummary, info.error)
  } catch (err) {
    renderIpDetailBody(selectedDetailIp, null, err instanceof Error ? err.message : String(err))
  }
})
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
      ipLabelCache.clear()
      await refreshGeoLiteStatus()
    }
  } catch (err) {
    geoliteStatusEl.textContent = err instanceof Error ? err.message : String(err)
  } finally {
    btnDownloadGeolite.disabled = false
  }
})
btnInfo.addEventListener('click', () => {
  updateCheckStatusEl.textContent = ''
  infoDialog.showModal()
})
btnCloseInfo.addEventListener('click', () => infoDialog.close())
btnInfoOk.addEventListener('click', () => infoDialog.close())
btnExport.addEventListener('click', () => exportDialog.showModal())
btnCloseExport.addEventListener('click', () => exportDialog.close())

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

providerEl.addEventListener('change', () => {
  applyProviderPreset(providerEl.value as ProviderPreset)
  updateAccountNamePlaceholder()
  syncAuthModeUi()
})

authModeEl.addEventListener('change', () => syncAuthModeUi())

btnOauthLogin.addEventListener('click', async () => {
  if (busy || dialogAccountId == null) {
    settingsStatusEl.textContent = t('settings.saveAccountFirst')
    return
  }
  // Persist current form (provider/auth mode) before starting the browser flow.
  setBusy(true)
  try {
    applySettings(await window.api.saveAccount(readAccountForm()))
    dialogAccountId = dialogAccountId ?? settings?.activeAccountId ?? null
    applySettings(await window.api.oauthLogin(dialogAccountId!))
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
  if (busy || dialogAccountId == null) return
  setBusy(true)
  try {
    applySettings(await window.api.oauthDisconnect(dialogAccountId))
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

accountSelectEl.addEventListener('change', () => {
  if (busy) return
  void switchActiveAccount(accountSelectEl.value)
})

settingsAccountSelectEl.addEventListener('change', () => {
  dialogAccountId =
    settingsAccountSelectEl.value === NEW_ACCOUNT_VALUE ? null : settingsAccountSelectEl.value
  fillSettingsAccountSelect()
  fillAccountForm(dialogAccount())
  scheduleMailboxOptionsRefresh()
})

btnNewAccount.addEventListener('click', () => {
  dialogAccountId = null
  fillSettingsAccountSelect()
  fillAccountForm(null)
  fillMailboxOptions([])
})

btnDeleteAccount.addEventListener('click', async () => {
  if (busy || dialogAccountId == null) return
  const account = dialogAccount()
  if (!account) return
  if (!confirm(t('settings.confirmDelete', { label: account.label }))) return
  setBusy(true)
  try {
    const wasActive = settings?.activeAccountId === dialogAccountId
    applySettings(await window.api.deleteAccount(dialogAccountId))
    dialogAccountId = settings?.activeAccountId ?? null
    fillSettingsAccountSelect()
    fillAccountForm(dialogAccount())
    settingsStatusEl.textContent = t('settings.accountDeleted')
    if (wasActive) {
      selectedReportId = null
      fullResult = null
      if (settings?.activeAccountId) {
        await switchActiveAccount(settings.activeAccountId)
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

filterRangeEl.addEventListener('change', () => {
  filterCustomWrap.classList.toggle('hidden', filterRangeEl.value !== 'custom')
  applyView()
})
filterFromEl.addEventListener('change', () => applyView())
filterToEl.addEventListener('change', () => applyView())
filterDomainEl.addEventListener('change', () => applyView())

btnTest.addEventListener('click', async () => {
  if (busy) return
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
  if (busy) return
  if (dialogAccountId == null) {
    settingsStatusEl.textContent = t('settings.saveAccountFirst')
    return
  }
  setBusy(true)
  try {
    const result = await window.api.clearCache(dialogAccountId)
    settingsStatusEl.textContent = result.message
    if (result.ok && dialogAccountId === settings?.activeAccountId) {
      fullResult = null
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
  if (busy) return
  setBusy(true)
  try {
    const accountInput = readAccountForm()
    // Always persist the edited account when one is selected (incl. display name only).
    const wantsAccountSave =
      dialogAccountId != null ||
      Boolean(accountInput.user || accountInput.host || accountInput.password)
    if (wantsAccountSave) {
      if (!accountInput.user || !accountInput.host) {
        showSettingsTab('account')
        throw new Error(t('settings.needUserHost'))
      }
      const before = new Set((settings?.accounts ?? []).map((a) => a.id))
      applySettings(await window.api.saveAccount(accountInput))
      if (dialogAccountId == null) {
        dialogAccountId = settings?.accounts.find((a) => !before.has(a.id))?.id ?? null
      }
    }
    applySettings(await window.api.saveGlobalSettings(readGlobalForm()))
    passwordEl.value = ''
    fillSettingsAccountSelect()
    fillAccountForm(dialogAccount())
    fillGlobalForm(settings!.global)
    applyUiLocale(settings!.global.language)
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

btnFetch.addEventListener('click', async () => {
  if (busy) return
  const account = activeAccount()
  if (!account || !accountHasAuth(account)) {
    openSettings()
    settingsStatusEl.textContent = t('settings.needCredentials')
    return
  }

  setBusy(true)
  setStatus(t('status.fetchStart'))
  progressEl.value = 0
  progressLabelEl.textContent = ''
  try {
    const result = await window.api.fetchSaved(account.id)
    selectedReportId = null
    showResult(result)
  } catch (err) {
    setStatus(err instanceof Error ? err.message : String(err), 'error')
  } finally {
    setBusy(false)
  }
})

btnOpenFiles.addEventListener('click', async () => {
  if (busy) return
  setBusy(true)
  try {
    const result = await window.api.openFiles()
    if (!result) return
    selectedReportId = null
    if (fullResult) {
      const map = new Map(fullResult.reports.map((r) => [r.reportId, r]))
      for (const r of result.reports) {
        map.set(r.reportId || `${r.orgName}|${r.domain}|${r.dateEnd}`, r)
      }
      const forensicMap = new Map((fullResult.forensicReports ?? []).map((r) => [r.id, r] as const))
      for (const r of result.forensicReports ?? []) forensicMap.set(r.id, r)
      showResult(
        analyzeFromReports([...map.values()], {
          skipped: fullResult.skipped + result.skipped,
          errors: [...fullResult.errors, ...result.errors].slice(0, 50),
          newReports: result.reports.length,
          newForensicReports: result.forensicReports?.length ?? 0,
          forensicReports: [...forensicMap.values()]
        }),
        t('status.localLoaded', { count: result.reports.length })
      )
    } else {
      showResult(result, t('status.localLoaded', { count: result.reports.length }))
    }
  } catch (err) {
    setStatus(err instanceof Error ? err.message : String(err), 'error')
  } finally {
    setBusy(false)
  }
})

/** Collect DKIM selectors for a domain from the loaded reports. */
function collectDkimSelectors(domain: string): string[] {
  if (!fullResult) return []
  const d = domain.toLowerCase()
  const selectors = new Set<string>()
  for (const report of fullResult.reports) {
    for (const rec of report.records) {
      if (
        report.domain.toLowerCase() === d ||
        rec.dkimDomain?.toLowerCase() === d ||
        rec.headerFrom?.toLowerCase() === d
      ) {
        for (const sel of rec.dkimSelectors ?? []) selectors.add(sel)
      }
    }
  }
  return [...selectors].sort()
}

btnDns.addEventListener('click', async () => {
  const domain = dnsDomainEl.value.trim() || filterDomainEl.value
  if (!domain) {
    dnsResultEl.textContent = t('dns.needDomain')
    dnsResultEl.className = 'dns-result error'
    return
  }
  const manualSelectors = dnsSelectorsEl.value
    .split(/[\s,;]+/)
    .map((s) => s.trim())
    .filter(Boolean)
  const selectors = manualSelectors.length > 0 ? manualSelectors : collectDkimSelectors(domain)

  dnsResultEl.textContent = t('dns.checking', { domain })
  dnsResultEl.className = 'dns-result'
  try {
    const result = await window.api.checkDns(domain, selectors)
    const dmarcLine = result.dmarc.found
      ? t('dns.dmarcFound', {
          policy: result.dmarc.policy ?? '?',
          rua: result.dmarc.rua ?? '—',
          ruf: result.dmarc.ruf ?? '—'
        })
      : `${t('dns.dmarcMissing')}${result.dmarc.error ? ` (${result.dmarc.error})` : ''}`
    const spfLine = result.spf.found
      ? t('dns.spfFound', { record: result.spf.records[0] })
      : `${t('dns.spfMissing')}${result.spf.error ? ` (${result.spf.error})` : ''}`

    let dkimHtml = ''
    if (result.dkim.selectors.length > 0) {
      dkimHtml = result.dkim.selectors
        .map((s) => {
          const state = s.found
            ? `<span class="pass">${escapeHtml(t('dns.dkimFound'))}</span>`
            : `<span class="fail">${escapeHtml(t('dns.dkimMissing'))}</span>`
          return t('dns.dkimLine', {
            selector: `<span class="mono">${escapeHtml(s.selector)}</span>`,
            state
          })
        })
        .join('<br />')
    } else {
      dkimHtml = escapeHtml(t('dns.dkimNone'))
    }

    dnsResultEl.innerHTML = `<strong>${escapeHtml(result.domain)}</strong><br />${escapeHtml(dmarcLine)}<br /><span class="mono">${escapeHtml(spfLine)}</span><br />${dkimHtml}`
    dnsResultEl.className = 'dns-result ok'
  } catch (err) {
    dnsResultEl.textContent = err instanceof Error ? err.message : String(err)
    dnsResultEl.className = 'dns-result error'
  }
})

async function doExport(format: 'json' | 'csv'): Promise<void> {
  if (!viewResult) return
  try {
    const res = await window.api.exportSave(viewResult, format)
    setStatus(res.message, res.ok ? 'ok' : '')
    if (res.ok) exportDialog.close()
  } catch (err) {
    setStatus(err instanceof Error ? err.message : String(err), 'error')
  }
}

btnExportCsv.addEventListener('click', () => void doExport('csv'))
btnExportJson.addEventListener('click', () => void doExport('json'))

// Drag & Drop
let dragDepth = 0
window.addEventListener('dragenter', (e) => {
  e.preventDefault()
  dragDepth += 1
  dropOverlay.classList.remove('hidden')
})
window.addEventListener('dragleave', (e) => {
  e.preventDefault()
  dragDepth = Math.max(0, dragDepth - 1)
  if (dragDepth === 0) dropOverlay.classList.add('hidden')
})
window.addEventListener('dragover', (e) => {
  e.preventDefault()
})
window.addEventListener('drop', (e) => {
  e.preventDefault()
  dragDepth = 0
  dropOverlay.classList.add('hidden')
  const files = [...(e.dataTransfer?.files ?? [])]
  if (!files.length || busy) return
  const paths = files
    .map((f) => {
      try {
        return window.api.getPathForFile(f)
      } catch {
        return ''
      }
    })
    .filter(Boolean)
  if (!paths.length) {
    setStatus(t('status.filesFailed'), 'error')
    return
  }
  void (async () => {
    setBusy(true)
    try {
      const result = await window.api.parsePaths(paths)
      selectedReportId = null
      showResult(result, t('status.filesLoaded', { count: result.reports.length }))
    } catch (err) {
      setStatus(err instanceof Error ? err.message : String(err), 'error')
    } finally {
      setBusy(false)
    }
  })()
})

window.api.onProgress(applyProgress)
window.api.onResult((result) => {
  // Ergebnisse anderer Konten (Auto-Abruf) nicht über die aktive Ansicht legen.
  if (
    result.accountId &&
    settings?.activeAccountId &&
    result.accountId !== settings.activeAccountId
  ) {
    return
  }
  selectedReportId = null
  showResult(result)
})
window.api.onUpdateStatus(applyUpdateStatus)

languageEl.addEventListener('change', () => {
  applyUiLocale(normalizeLocale(languageEl.value))
})

void (async () => {
  try {
    aboutVersionEl.textContent = await window.api.getAppVersion()
    await loadSettings()
    const cached = await window.api.loadCache()
    if (cached && cached.reports.length > 0) {
      showResult(cached, t('status.cached', { count: cached.aggregate.reportCount }))
    }
  } catch (err) {
    setStatus(err instanceof Error ? err.message : String(err), 'error')
  }
})()

/** Helpers used by `npm run screenshots` (Electron capture script). */
window.__dmarcScreenshot = {
  async prepareDemo(): Promise<void> {
    applyUiLocale('de')
    applySettings(buildDemoSettings())
    fillGlobalForm(settings!.global)
    selectedReportId = null
    Object.keys(drill).forEach((k) => delete drill[k as keyof typeof drill])
    showResult(buildDemoAnalyzeResult(), t('status.cached', { count: 12 }))
    dnsDomainEl.value = 'example.com'
    dnsResultEl.innerHTML = DEMO_DNS_HTML
    dnsResultEl.className = 'dns-result ok'
    // Seed PTR labels without calling the network.
    const demoIp = (
      ip: string,
      ptr: string | null,
      provider: string | null,
      extra: Partial<IpInfo> = {}
    ): void => {
      ipLabelCache.set(ip, {
        ip,
        ptr,
        provider,
        country: extra.country ?? null,
        countryCode: extra.countryCode ?? null,
        city: extra.city ?? null,
        asn: extra.asn ?? null,
        asOrg: extra.asOrg ?? null,
        cloudProvider: extra.cloudProvider ?? null,
        dnsblHits: extra.dnsblHits ?? [],
        geoSource: extra.geoSource ?? 'none'
      })
    }
    demoIp('192.0.2.10', 'mail-a.example.net', 'Example Net', {
      countryCode: 'DE',
      city: 'Berlin',
      asn: 64496,
      cloudProvider: null
    })
    demoIp('192.0.2.40', 'smtp.example.net', 'Example Net', {
      countryCode: 'DE',
      asn: 64496
    })
    demoIp('198.51.100.20', null, null, {
      countryCode: 'US',
      asn: 15169,
      cloudProvider: 'Google',
      dnsblHits: []
    })
    demoIp('198.51.100.55', 'mta.yahoo.example', 'Yahoo', {
      countryCode: 'US',
      asn: 10310
    })
    demoIp('203.0.113.15', null, null, {
      countryCode: 'NL',
      dnsblHits: ['spamhaus-zen']
    })
    demoIp('2001:db8:1::10', 'ipv6.example.net', 'Example Net', {
      countryCode: 'DE',
      asn: 64496
    })
    domainHealthCache = [
      {
        domain: 'example.com',
        total: 100,
        passing: 98,
        failing: 2,
        passRate: 98,
        dkimSelectors: ['selector1'],
        dmarcPolicy: 'reject',
        spfOk: true,
        dkimOk: true,
        status: 'ok',
        reasons: ['health.reason.ok']
      }
    ]
    renderDomainAmpel(domainHealthCache)
    applyView()
    settingsDialog.close()
    await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)))
  },
  openSettingsDemo(): void {
    openSettings()
    showSettingsTab('account')
  },
  closeSettings(): void {
    settingsDialog.close()
  },
  async scrollTo(selector: string): Promise<void> {
    const el = document.querySelector(selector)
    if (el) el.scrollIntoView({ block: 'start' })
    await new Promise((r) => setTimeout(r, 200))
  },
  async selectFirstReport(): Promise<void> {
    const first = fullResult?.reports[0]
    if (!first) return
    selectedReportId = first.reportId
    renderReports(viewResult)
    renderDetail(first)
    await new Promise((r) => setTimeout(r, 100))
  }
}
