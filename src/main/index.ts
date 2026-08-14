import {
  app,
  BrowserWindow,
  ipcMain,
  dialog,
  Menu,
  nativeTheme,
  Notification,
  Tray
} from 'electron'
import { join, basename } from 'path'
import { tmpdir } from 'os'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs'
import { electronApp, optimizer, is } from '@electron-toolkit/utils'
import { createAppIcon, createTrayIcon } from './icon'
import type {
  AccountPublic,
  AccountSettingsInput,
  AnalyzeResult,
  AppTheme,
  EmailInspectResult,
  GlobalSettings,
  ReportRow
} from '../shared/types'
import { normalizeTheme } from '../shared/theme'
import {
  LOCAL_IMPORT_ACCOUNT_KEY,
  accountKeyFor,
  clearCache,
  getDnsHealthCache,
  loadCachedReports
} from './cache'
import { analyzeFromReports } from '../shared/analyze'
import {
  isMonthlyReportDue,
  monthlyReportFilename,
  periodForReports,
  previousMonthRange
} from '../shared/report-period'
import {
  buildPdfReport,
  buildEmailInspectPdf,
  defaultReportDir,
  domainHealthFromReports,
  forensicInPeriod,
  groupReportsByDomain,
  reportsInPeriod,
  writeReportFile
} from './pdf-report'
import { emailInspectPdfFilename } from '../shared/email-inspect-html'
import { inspectEmailBuffer, inspectEmailText } from './email-inspect'
import { importLocalFiles, loadLocalImportResult, type ImportTargetAccount } from './import'
import { checkDomainDns } from './dnscheck'
import { checkTransportSecurity } from './transport'
import { expandSpf } from './spf-expand'
import { exportReportZip, exportReportsCsv, exportReportsJson } from './export'
import {
  createMailbox,
  fetchAndAnalyze,
  listMailboxes,
  loadCachedAnalyzeResult,
  previousFailingTotal,
  testConnection
} from './imap'
import { clearIpInfoMemoryCache, resolveIps } from './ipinfo'
import { lookupRdap } from './rdap'
import { buildDomainHealth } from './domainhealth'
import { downloadGeoLite, getGeoLiteStatus } from './geoip'
import {
  beginOAuthLogin,
  deleteAccount,
  disconnectOAuth,
  exportSecretsForMigration,
  getMaxmindLicenseKey,
  hasEncryptedSecrets,
  importSecretsFromMigration,
  isIgnoredSource,
  loadSettings,
  parseIgnoredSources,
  resolveAccountConnection,
  resolveInputConnection,
  applyOpenAtLogin,
  applyNativeTheme,
  saveAccount,
  saveGlobalSettings,
  secretsDecryptable,
  setActiveAccount,
  setMonthlyReportRun
} from './settings'
import { setupAutoUpdater } from './updater'
import { runScreenshotCapture, wantsScreenshotCapture } from './screenshots'
import { t } from '../shared/i18n'
import { applyAppIdentityBeforeReady, ensureSafeStorageIdentity } from './app-identity'
import { fixPackagedExecEnv, relaunchApp } from './relaunch'
import { openExternalSafe } from './open-external'

function accountReady(account: AccountPublic): boolean {
  return Boolean(account.user && (account.hasPassword || account.hasOAuth))
}

/** Cache owner for file imports: the active account, or the local slot without one. */
function importTargetAccount(): ImportTargetAccount | null {
  try {
    const settingsPub = loadSettings()
    const account = settingsPub.accounts.find((a) => a.id === settingsPub.activeAccountId)
    if (!account?.user || !account.host) return null
    return { user: account.user, host: account.host, mailbox: account.mailbox }
  } catch {
    return null
  }
}

app.disableHardwareAcceleration()
app.commandLine.appendSwitch('disable-gpu')
if (process.platform === 'linux') {
  app.commandLine.appendSwitch('no-sandbox')
  // Avoid Chromium FATAL on /dev/shm shared-memory create (ESRCH) when spawning windows.
  app.commandLine.appendSwitch('disable-dev-shm-usage')
}

let mainWindow: BrowserWindow | null = null
let noticesWindow: BrowserWindow | null = null
let tray: Tray | null = null
let isQuitting = false
let autoFetchTimer: ReturnType<typeof setInterval> | null = null
let monthlyReportTimer: ReturnType<typeof setInterval> | null = null
let monthlyReportInFlight = false
let fetchInFlight = false
/** True when the app was launched at login as a hidden background instance. */
let startHidden = false
/** Tray badge: new reports arrived while the window was not in view. */
let trayNeedsAttention = false

function shouldStartHidden(): boolean {
  if (process.argv.includes('--hidden')) return true
  try {
    return Boolean(app.getLoginItemSettings().wasOpenedAsHidden)
  } catch {
    return false
  }
}

function createWindow(): BrowserWindow {
  const appIcon = createAppIcon()
  const capture = wantsScreenshotCapture()

  const win = new BrowserWindow({
    width: capture ? 1400 : 1280,
    height: capture ? 960 : 900,
    minWidth: 960,
    minHeight: 680,
    show: false,
    autoHideMenuBar: true,
    title: 'DMARC Lighthouse',
    backgroundColor: nativeTheme.shouldUseDarkColors ? '#121820' : '#eef1f4',
    ...(appIcon.isEmpty() ? {} : { icon: appIcon }),
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      // sandbox:true breaks this preload (CommonJS require) and can leave a blank window.
      sandbox: false,
      contextIsolation: true,
      nodeIntegration: false
    }
  })

  if (!appIcon.isEmpty()) {
    win.setIcon(appIcon)
  }

  win.on('ready-to-show', () => {
    if (!appIcon.isEmpty()) {
      win.setIcon(appIcon)
    }
    // Autostart + tray: stay in the background until the user opens the window.
    if (!capture && startHidden && loadSettings().global.runInTray) {
      updateTray()
      return
    }
    win.show()
    if (capture) {
      void runScreenshotCapture(win).catch((err) => {
        console.error(err)
        app.exit(1)
      })
    }
  })

  win.on('close', (event) => {
    // With tray mode enabled, closing the window keeps the app (and auto-fetch) running.
    if (!isQuitting && loadSettings().global.runInTray) {
      event.preventDefault()
      win.hide()
    }
  })

  win.on('show', () => {
    clearTrayAttention()
  })

  win.webContents.setWindowOpenHandler((details) => {
    void openExternalSafe(details.url).catch((err) => {
      console.error(err)
    })
    return { action: 'deny' }
  })

  if (is.dev && process.env['ELECTRON_RENDERER_URL']) {
    win.loadURL(process.env['ELECTRON_RENDERER_URL'])
  } else {
    win.loadFile(join(__dirname, '../renderer/index.html'))
  }

  return win
}

function showMainWindow(): void {
  clearTrayAttention()
  if (!mainWindow || mainWindow.isDestroyed()) {
    mainWindow = createWindow()
    return
  }
  if (mainWindow.isMinimized()) mainWindow.restore()
  mainWindow.show()
  mainWindow.focus()
}

function isMainWindowInView(): boolean {
  if (!mainWindow || mainWindow.isDestroyed()) return false
  return mainWindow.isVisible() && !mainWindow.isMinimized()
}

function applyTrayIconAndTooltip(): void {
  if (!tray) return
  const icon = createTrayIcon(trayNeedsAttention)
  if (!icon.isEmpty()) tray.setImage(icon)
  tray.setToolTip(trayNeedsAttention ? t('main.trayTooltipNew') : t('app.title'))
  if (process.platform === 'darwin' && app.dock) {
    app.dock.setBadge(trayNeedsAttention ? '•' : '')
  }
}

function setTrayAttention(on: boolean): void {
  if (trayNeedsAttention === on) {
    if (on) applyTrayIconAndTooltip()
    return
  }
  trayNeedsAttention = on
  applyTrayIconAndTooltip()
}

function clearTrayAttention(): void {
  setTrayAttention(false)
}

function markTrayAttentionIfHidden(): void {
  if (!loadSettings().global.runInTray) return
  if (isMainWindowInView()) return
  updateTray()
  setTrayAttention(true)
}

function updateTray(): void {
  const wantTray = loadSettings().global.runInTray
  if (wantTray && !tray) {
    const icon = createTrayIcon(trayNeedsAttention)
    tray = new Tray(icon.isEmpty() ? createAppIcon() : icon)
    tray.on('click', () => showMainWindow())
  } else if (!wantTray && tray) {
    tray.destroy()
    tray = null
    trayNeedsAttention = false
    if (process.platform === 'darwin' && app.dock) {
      app.dock.setBadge('')
    }
    return
  }
  if (!tray) return
  applyTrayIconAndTooltip()
  tray.setContextMenu(
    Menu.buildFromTemplate([
      { label: t('main.trayShow'), click: () => showMainWindow() },
      { label: t('main.trayFetch'), click: () => void runAutoFetchAll() },
      { type: 'separator' },
      {
        label: t('main.trayQuit'),
        click: () => {
          isQuitting = true
          app.quit()
        }
      }
    ])
  )
}

function notify(body: string): void {
  if (!Notification.isSupported()) return
  const n = new Notification({ title: 'DMARC Lighthouse', body })
  n.on('click', () => showMainWindow())
  n.show()
}

/** Pass rate over reports whose window ends within the last `days` days, or null without data. */
function passRateLastDays(reports: ReportRow[], days: number): number | null {
  const cutoff = Date.now() - days * 86_400_000
  let total = 0
  let passing = 0
  for (const r of reports) {
    const end = new Date(r.dateEnd || r.dateBegin).getTime()
    if (Number.isNaN(end) || end < cutoff) continue
    total += r.total
    passing += r.passing
  }
  if (total === 0) return null
  return Math.round((passing / total) * 1000) / 10
}

function runAlerts(account: AccountPublic, prevFailing: number, result: AnalyzeResult): void {
  const global = loadSettings().global
  const suffix = loadSettings().accounts.length > 1 ? ` (${account.label})` : ''

  if (global.notifyOnFail && result.aggregate.failing > prevFailing) {
    const delta = result.aggregate.failing - prevFailing
    notify(
      t('main.alertFail', {
        delta,
        total: result.aggregate.failing,
        suffix
      })
    )
  }

  if (global.passRateAlertThreshold > 0 && (result.newReports ?? 0) > 0) {
    const rate = passRateLastDays(result.reports, 7)
    if (rate != null && rate < global.passRateAlertThreshold) {
      notify(
        t('main.alertPassRate', {
          rate: rate.toFixed(1),
          threshold: global.passRateAlertThreshold,
          suffix
        })
      )
    }
  }

  if (global.notifyNewSource && result.newSourceIps && result.newSourceIps.length > 0) {
    const matchers = parseIgnoredSources(global.ignoredSources)
    const relevant = result.newSourceIps.filter((ip) => !isIgnoredSource(ip, matchers))
    if (relevant.length > 0) {
      const shown = relevant.slice(0, 3).join(', ')
      const more = relevant.length > 3 ? t('main.alertMore', { count: relevant.length - 3 }) : ''
      notify(t('main.alertNewSource', { shown, more, suffix }))
    }
  }
}

async function runSavedFetch(accountId?: string | null): Promise<AnalyzeResult> {
  if (fetchInFlight) {
    throw new Error(t('main.fetchInFlight'))
  }
  fetchInFlight = true
  try {
    return await fetchAccount(accountId)
  } finally {
    fetchInFlight = false
  }
}

async function fetchAccount(accountId?: string | null): Promise<AnalyzeResult> {
  const settingsPub = loadSettings()
  const id = accountId ?? settingsPub.activeAccountId
  const account = settingsPub.accounts.find((a) => a.id === id)
  if (!account) throw new Error(t('main.noAccount'))

  const connection = await resolveAccountConnection(account.id)
  const prevFailing = previousFailingTotal(connection)
  const result = await fetchAndAnalyze(connection, (progress) => {
    mainWindow?.webContents.send('imap:progress', progress)
  })
  result.accountId = account.id
  runAlerts(account, prevFailing, result)
  if ((result.newReports ?? 0) > 0) {
    markTrayAttentionIfHidden()
  }
  mainWindow?.webContents.send('imap:result', result)
  return result
}

/** Fetch all configured accounts sequentially (auto-fetch / tray action). */
async function runAutoFetchAll(): Promise<void> {
  if (fetchInFlight) return
  fetchInFlight = true
  try {
    const settingsPub = loadSettings()
    for (const account of settingsPub.accounts) {
      if (!accountReady(account)) continue
      try {
        await fetchAccount(account.id)
      } catch (err) {
        mainWindow?.webContents.send('imap:progress', {
          phase: 'error',
          processed: 0,
          total: 0,
          parsed: 0,
          skipped: 0,
          message: `${account.label}: ${err instanceof Error ? err.message : String(err)}`
        })
      }
    }
  } finally {
    fetchInFlight = false
  }
}

function stopAutoFetch(): void {
  if (autoFetchTimer) {
    clearInterval(autoFetchTimer)
    autoFetchTimer = null
  }
}

function scheduleAutoFetch(): void {
  stopAutoFetch()
  const settingsPub = loadSettings()
  const minutes = settingsPub.global.autoFetchMinutes
  const hasAccount = settingsPub.accounts.some((a) => accountReady(a))
  if (!minutes || minutes <= 0 || !hasAccount) return

  autoFetchTimer = setInterval(() => {
    void runAutoFetchAll()
  }, minutes * 60_000)
}

/** Cache slots a monthly report can be built from: IMAP accounts plus local imports. */
function reportSources(): Array<{ key: string; label: string | null }> {
  const settingsPub = loadSettings()
  const sources: Array<{ key: string; label: string | null }> = settingsPub.accounts
    .filter((a) => a.user && a.host)
    .map((a) => ({ key: accountKeyFor(a.user, a.host, a.mailbox), label: a.label }))
  if (sources.length === 0) {
    sources.push({ key: LOCAL_IMPORT_ACCOUNT_KEY, label: null })
  }
  return sources
}

/**
 * Write one PDF per domain. An IMAP account is only the mailbox.
 * `scheduled` covers the finished calendar month; `now` also includes domains
 * that only have data in a later month (their latest month).
 */
async function runMonthlyReport(mode: 'scheduled' | 'now' = 'scheduled'): Promise<string[]> {
  if (monthlyReportInFlight) return []
  monthlyReportInFlight = true
  try {
    return await writeMonthlyReports(mode)
  } finally {
    monthlyReportInFlight = false
  }
}

async function writeMonthlyReports(mode: 'scheduled' | 'now'): Promise<string[]> {
  const global = loadSettings().global
  const dir = global.pdfMonthlyDir.trim() || defaultReportDir()
  const scheduledPeriod = previousMonthRange()

  const sources = reportSources().map((source) => {
    const cached = loadCachedReports(source.key)
    return {
      label: source.label,
      reports: cached.reports,
      forensicReports: cached.forensicReports
    }
  })

  const written: string[] = []
  for (const slice of groupReportsByDomain(sources)) {
    const stamps = [
      ...slice.reports.flatMap((r) => [r.dateBegin, r.dateEnd]),
      ...slice.forensicReports.map((f) => f.arrivalDate ?? '')
    ].filter(Boolean)
    const period = mode === 'scheduled' ? scheduledPeriod : periodForReports(stamps)
    if (!period) continue
    const reports = reportsInPeriod(slice.reports, period)
    const forensicReports = forensicInPeriod(slice.forensicReports, period)
    if (reports.length === 0 && forensicReports.length === 0) continue

    const result = analyzeFromReports(reports, { fromCache: true, forensicReports })
    const pdf = await buildPdfReport(result, {
      month: period.month,
      domain: slice.domain,
      account: slice.accountLabels.length === 1 ? slice.accountLabels[0] : null,
      domains: domainHealthFromReports(reports, (domain) => getDnsHealthCache(domain)),
      host: mainWindow
    })
    written.push(writeReportFile(dir, monthlyReportFilename(slice.domain, period.month), pdf))
  }

  setMonthlyReportRun(new Date().toISOString())
  if (written.length > 0) {
    notify(t('main.pdfMonthlyDone', { count: written.length, dir }))
  }
  return written
}

function stopMonthlyReport(): void {
  if (monthlyReportTimer) {
    clearInterval(monthlyReportTimer)
    monthlyReportTimer = null
  }
}

/**
 * Check hourly whether the finished month still needs its report. An interval is
 * enough because the run is idempotent per month and survives a sleeping laptop.
 */
function scheduleMonthlyReport(): void {
  stopMonthlyReport()
  if (!loadSettings().global.pdfMonthlyEnabled) return
  const tick = (): void => {
    const global = loadSettings().global
    if (!global.pdfMonthlyEnabled) return
    if (!isMonthlyReportDue(global.pdfMonthlyLastRun || null)) return
    void runMonthlyReport().catch((err) => {
      notify(
        t('main.pdfMonthlyFailed', { message: err instanceof Error ? err.message : String(err) })
      )
    })
  }
  monthlyReportTimer = setInterval(tick, 60 * 60_000)
  setTimeout(tick, 30_000)
}

function thirdPartyNoticesPath(): string {
  if (app.isPackaged) {
    return join(process.resourcesPath, 'THIRD_PARTY_NOTICES.txt')
  }
  return join(__dirname, '../../THIRD_PARTY_NOTICES.txt')
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

/** Show notices in-app — shell.openPath often hangs on Linux and never resolves IPC. */
async function openThirdPartyNoticesWindow(): Promise<{ ok: boolean; message: string }> {
  const target = thirdPartyNoticesPath()
  if (!existsSync(target)) {
    return { ok: false, message: t('about.noticesMissing') }
  }

  if (noticesWindow && !noticesWindow.isDestroyed()) {
    noticesWindow.focus()
    return { ok: true, message: '' }
  }

  const body = escapeHtml(readFileSync(target, 'utf8'))
  const title = escapeHtml(t('about.openLicenses'))
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>${title}</title>
  <style>
    :root { color-scheme: light dark; }
    body {
      margin: 0;
      padding: 16px 18px 24px;
      font: 12px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      color: #1a2332;
      background: #f7f9fb;
      white-space: pre-wrap;
      word-break: break-word;
    }
    @media (prefers-color-scheme: dark) {
      body {
        color: #e8eef3;
        background: #121820;
      }
    }
  </style>
</head>
<body>${body}</body>
</html>`

  // Temp HTML + loadFile: data: URLs fail (ERR_FAILED) for large notices; avoids .txt MIME quirks.
  const noticesDir = mkdtempSync(join(tmpdir(), 'dmarc-lighthouse-notices-'))
  const htmlPath = join(noticesDir, 'notices.html')
  writeFileSync(htmlPath, html, 'utf8')

  const cleanupNoticesDir = (): void => {
    try {
      rmSync(noticesDir, { recursive: true, force: true })
    } catch {
      // ignore cleanup errors
    }
  }

  const appIcon = createAppIcon()
  noticesWindow = new BrowserWindow({
    width: 780,
    height: 640,
    minWidth: 480,
    minHeight: 360,
    title: t('about.openLicenses'),
    autoHideMenuBar: true,
    parent: mainWindow && !mainWindow.isDestroyed() ? mainWindow : undefined,
    ...(appIcon.isEmpty() ? {} : { icon: appIcon }),
    webPreferences: {
      // Match main window: sandbox:true crashes the renderer on Linux (/dev/shm FATAL → blank window).
      sandbox: false,
      contextIsolation: true,
      nodeIntegration: false
    }
  })

  noticesWindow.on('closed', () => {
    noticesWindow = null
    cleanupNoticesDir()
  })

  try {
    await noticesWindow.loadFile(htmlPath)
  } catch (error) {
    if (noticesWindow && !noticesWindow.isDestroyed()) {
      noticesWindow.destroy()
    }
    noticesWindow = null
    cleanupNoticesDir()
    throw error
  }
  return { ok: true, message: '' }
}

function registerIpc(): void {
  ipcMain.handle('app:getVersion', () => app.getVersion())

  ipcMain.handle('app:openThirdPartyNotices', async () => {
    try {
      return await openThirdPartyNoticesWindow()
    } catch (e) {
      return { ok: false, message: e instanceof Error ? e.message : String(e) }
    }
  })

  ipcMain.handle('settings:load', () => loadSettings())

  ipcMain.handle('settings:saveAccount', (_event, input: AccountSettingsInput) => {
    const saved = saveAccount(input)
    scheduleAutoFetch()
    return saved
  })

  ipcMain.handle('settings:deleteAccount', (_event, id: string) => {
    // Drop the account's cache along with the account itself.
    try {
      const account = loadSettings().accounts.find((a) => a.id === id)
      if (account) {
        clearCache(accountKeyFor(account.user, account.host, account.mailbox))
      }
    } catch {
      // Cache-Aufräumen ist optional.
    }
    const saved = deleteAccount(id)
    scheduleAutoFetch()
    return saved
  })

  ipcMain.handle('settings:setActiveAccount', (_event, id: string) => setActiveAccount(id))

  ipcMain.handle('settings:saveGlobal', (_event, input: GlobalSettings) => {
    const saved = saveGlobalSettings(input)
    clearIpInfoMemoryCache()
    applyOpenAtLogin(saved.global)
    applyNativeTheme(saved.global.theme)
    scheduleAutoFetch()
    scheduleMonthlyReport()
    updateTray()
    return saved
  })

  ipcMain.handle('settings:previewTheme', (_event, theme: AppTheme) => {
    applyNativeTheme(normalizeTheme(theme))
  })

  ipcMain.handle('imap:test', async (_event, input: AccountSettingsInput) => {
    const connection = await resolveInputConnection(input)
    return testConnection(connection)
  })

  ipcMain.handle('imap:listMailboxes', async (_event, input: AccountSettingsInput) => {
    const connection = await resolveInputConnection(input)
    return listMailboxes(connection)
  })

  ipcMain.handle(
    'imap:createMailbox',
    async (_event, input: AccountSettingsInput, path: string) => {
      const connection = await resolveInputConnection(input)
      return createMailbox(connection, path ?? '')
    }
  )

  ipcMain.handle('imap:fetchSaved', async (_event, accountId?: string | null) =>
    runSavedFetch(accountId)
  )

  ipcMain.handle('oauth:login', async (_event, accountId: string) => beginOAuthLogin(accountId))

  ipcMain.handle('oauth:disconnect', (_event, accountId: string) => disconnectOAuth(accountId))

  ipcMain.handle('cache:load', (_event, accountId?: string | null) => {
    try {
      const settingsPub = loadSettings()
      const id = accountId ?? settingsPub.activeAccountId
      const account = settingsPub.accounts.find((a) => a.id === id)
      // No usable account yet: show reports that were imported from files.
      if (!account?.user || !account.host) return loadLocalImportResult()
      const result = loadCachedAnalyzeResult({
        provider: account.provider,
        host: account.host,
        port: account.port,
        secure: account.secure,
        user: account.user,
        authMode: account.authMode,
        mailbox: account.mailbox,
        archiveMailbox: account.archiveMailbox,
        subjectFilter: account.subjectFilter,
        markSeenAfterFetch: account.markSeenAfterFetch
      })
      result.accountId = id ?? undefined
      return result
    } catch {
      return null
    }
  })

  ipcMain.handle('cache:clear', (_event, accountId?: string | null) => {
    const settingsPub = loadSettings()
    const id = accountId ?? settingsPub.activeAccountId
    const account = settingsPub.accounts.find((a) => a.id === id)
    if (!account) {
      // Without an account the only cached data can come from file imports.
      clearCache(LOCAL_IMPORT_ACCOUNT_KEY)
      return { ok: true, message: t('main.cacheCleared') }
    }
    clearCache(accountKeyFor(account.user, account.host, account.mailbox))
    return { ok: true, message: t('main.cacheCleared') }
  })

  ipcMain.handle('ip:resolve', async (_event, ips: string[]) => resolveIps(ips ?? []))

  ipcMain.handle('ip:rdap', async (_event, ip: string) => {
    const settingsPub = loadSettings()
    if (!settingsPub.global.rdapEnabled || !settingsPub.global.enrichmentEnabled) {
      return {
        ip: ip ?? '',
        org: null,
        country: null,
        cidr: null,
        abuseEmail: null,
        rawSummary: null,
        error: t('enrichment.rdapDisabled')
      }
    }
    return lookupRdap(ip ?? '')
  })

  ipcMain.handle('dns:check', async (_event, domain: string, selectors?: string[]) =>
    checkDomainDns(domain, selectors ?? [])
  )

  ipcMain.handle('dns:expandSpf', async (_event, domain: string, record?: string | null) =>
    expandSpf(domain ?? '', { record: record ?? null })
  )

  ipcMain.handle('dns:transport', async (_event, domain: string) =>
    checkTransportSecurity(domain ?? '')
  )

  ipcMain.handle('dns:healthBatch', async (_event, reports: ReportRow[]) =>
    buildDomainHealth(Array.isArray(reports) ? reports : [])
  )

  ipcMain.handle('enrichment:geoLiteStatus', () => getGeoLiteStatus())

  ipcMain.handle('enrichment:downloadGeoLite', async (_event, licenseKey?: string) => {
    const typed = typeof licenseKey === 'string' ? licenseKey.trim() : ''
    const key = typed || getMaxmindLicenseKey()
    return downloadGeoLite(key)
  })

  ipcMain.handle('files:open', async () => {
    const openOptions = {
      title: t('main.openReports'),
      properties: ['openFile', 'multiSelections'] as Array<'openFile' | 'multiSelections'>,
      filters: [
        { name: 'DMARC Reports', extensions: ['xml', 'gz', 'zip', 'eml', 'mime'] },
        { name: 'Alle Dateien / All files', extensions: ['*'] }
      ]
    }
    const result = mainWindow
      ? await dialog.showOpenDialog(mainWindow, openOptions)
      : await dialog.showOpenDialog(openOptions)
    if (result.canceled || result.filePaths.length === 0) return null

    const buffers = result.filePaths.map((p) => ({
      name: basename(p),
      data: readFileSync(p)
    }))
    return importLocalFiles(buffers, importTargetAccount())
  })

  ipcMain.handle(
    'files:parseBuffers',
    async (_event, files: Array<{ name?: string; data?: ArrayBuffer | Uint8Array }>) => {
      const buffers: Array<{ name: string; data: Buffer }> = []
      for (const [index, f] of (Array.isArray(files) ? files : []).entries()) {
        if (!f?.data) continue
        const rawName = typeof f.name === 'string' && f.name.trim() ? f.name : `file-${index}`
        buffers.push({
          name: basename(rawName),
          data: Buffer.from(f.data instanceof ArrayBuffer ? new Uint8Array(f.data) : f.data)
        })
      }
      return importLocalFiles(buffers, importTargetAccount())
    }
  )

  ipcMain.handle('email:open', async () => {
    const openOptions = {
      title: t('main.openEmail'),
      properties: ['openFile'] as Array<'openFile'>,
      filters: [
        { name: 'E-Mail', extensions: ['eml', 'emlx', 'msg', 'mime', 'txt'] },
        { name: 'Alle Dateien / All files', extensions: ['*'] }
      ]
    }
    const picked = mainWindow
      ? await dialog.showOpenDialog(mainWindow, openOptions)
      : await dialog.showOpenDialog(openOptions)
    if (picked.canceled || picked.filePaths.length === 0) return null
    const filePath = picked.filePaths[0]
    return inspectEmailBuffer(readFileSync(filePath), basename(filePath))
  })

  ipcMain.handle(
    'email:parse',
    async (_event, input: { name?: string; data?: ArrayBuffer | Uint8Array; text?: string }) => {
      if (typeof input?.text === 'string') {
        return inspectEmailText(input.text, input.name?.trim() || 'paste.eml')
      }
      if (!input?.data) return { ok: false, message: t('email.emptyFile') }
      const rawName =
        typeof input.name === 'string' && input.name.trim() ? input.name : 'message.eml'
      const bytes = input.data instanceof ArrayBuffer ? new Uint8Array(input.data) : input.data
      return inspectEmailBuffer(bytes, basename(rawName))
    }
  )

  ipcMain.handle('email:pdf', async (_event, result: EmailInspectResult) => {
    if (!result || typeof result !== 'object' || !Array.isArray(result.checks)) {
      return { ok: false, message: t('email.pdfEmpty') }
    }
    const pdf = await buildEmailInspectPdf(result, { host: mainWindow })
    const saveOptions = {
      title: t('main.saveEmailPdf'),
      defaultPath: emailInspectPdfFilename(
        typeof result.fileName === 'string' ? result.fileName : 'message'
      ),
      filters: [{ name: 'PDF', extensions: ['pdf'] }]
    }
    const save = mainWindow
      ? await dialog.showSaveDialog(mainWindow, saveOptions)
      : await dialog.showSaveDialog(saveOptions)
    if (save.canceled || !save.filePath) return { ok: false, message: t('main.cancelled') }
    writeFileSync(save.filePath, pdf)
    return { ok: true, message: t('main.saved', { path: save.filePath }) }
  })

  ipcMain.handle('export:save', async (_event, result: AnalyzeResult, format: 'json' | 'csv') => {
    const defaultPath = format === 'json' ? 'dmarc-reports.json' : 'dmarc-reports.csv'
    const saveOptions = {
      title: t('main.saveExport'),
      defaultPath,
      filters:
        format === 'json'
          ? [{ name: 'JSON', extensions: ['json'] }]
          : [{ name: 'CSV', extensions: ['csv'] }]
    }
    const save = mainWindow
      ? await dialog.showSaveDialog(mainWindow, saveOptions)
      : await dialog.showSaveDialog(saveOptions)
    if (save.canceled || !save.filePath) return { ok: false, message: t('main.cancelled') }

    const content = format === 'json' ? exportReportsJson(result) : exportReportsCsv(result)
    writeFileSync(save.filePath, content, 'utf8')
    return { ok: true, message: t('main.saved', { path: save.filePath }) }
  })

  ipcMain.handle('export:reportZip', async (_event, report: ReportRow) => {
    if (!report?.reportId) return { ok: false, message: t('main.exportReportMissing') }
    const { filename, data } = exportReportZip(report)
    const saveOptions = {
      title: t('main.saveReportZip'),
      defaultPath: filename,
      filters: [{ name: 'ZIP', extensions: ['zip'] }]
    }
    const save = mainWindow
      ? await dialog.showSaveDialog(mainWindow, saveOptions)
      : await dialog.showSaveDialog(saveOptions)
    if (save.canceled || !save.filePath) return { ok: false, message: t('main.cancelled') }
    writeFileSync(save.filePath, data)
    return { ok: true, message: t('main.saved', { path: save.filePath }) }
  })

  ipcMain.handle(
    'report:pdf',
    async (_event, result: AnalyzeResult, options: { domain?: string | null } = {}) => {
      const domain = options.domain?.trim() || null
      const pdf = await buildPdfReport(result, {
        domain,
        domains: domainHealthFromReports(result.reports, (d) => getDnsHealthCache(d)),
        host: mainWindow
      })
      const saveOptions = {
        title: t('main.savePdf'),
        defaultPath: monthlyReportFilename(domain, new Date().toISOString().slice(0, 10)),
        filters: [{ name: 'PDF', extensions: ['pdf'] }]
      }
      const save = mainWindow
        ? await dialog.showSaveDialog(mainWindow, saveOptions)
        : await dialog.showSaveDialog(saveOptions)
      if (save.canceled || !save.filePath) return { ok: false, message: t('main.cancelled') }
      writeFileSync(save.filePath, pdf)
      return { ok: true, message: t('main.saved', { path: save.filePath }) }
    }
  )

  ipcMain.handle('report:chooseDir', async () => {
    const options = { properties: ['openDirectory' as const, 'createDirectory' as const] }
    const picked = mainWindow
      ? await dialog.showOpenDialog(mainWindow, options)
      : await dialog.showOpenDialog(options)
    if (picked.canceled || picked.filePaths.length === 0) return { ok: false, dir: '' }
    return { ok: true, dir: picked.filePaths[0] }
  })

  ipcMain.handle('report:monthlyNow', async () => {
    const written = await runMonthlyReport('now')
    if (written.length === 0) return { ok: false, message: t('main.pdfMonthlyEmpty') }
    return { ok: true, message: t('main.saved', { path: written.join(', ') }) }
  })
}

// Stable Windows/macOS update + uninstall identity (must match electron-builder appId).
electronApp.setAppUserModelId('de.codemacher.dmarcviewer')

// AppImage updates may leave APPIMAGE pointing at a deleted versioned file.
fixPackagedExecEnv()

// userData + safeStorage-bound app name (must stay stable — see app-identity.ts).
applyAppIdentityBeforeReady()

app.whenReady().then(() => {
  app.on('browser-window-created', (_, window) => {
    optimizer.watchWindowShortcuts(window)
  })

  const capture = wantsScreenshotCapture()
  if (
    !capture &&
    !ensureSafeStorageIdentity({
      hasEncryptedSecrets,
      secretsDecryptable,
      exportSecrets: exportSecretsForMigration,
      importSecrets: importSecretsFromMigration,
      relaunch: relaunchApp
    })
  ) {
    return
  }

  const settings = loadSettings()
  startHidden = capture ? false : shouldStartHidden()
  if (!capture) applyOpenAtLogin(settings.global)
  applyNativeTheme(settings.global.theme)

  registerIpc()
  if (!capture) setupAutoUpdater(() => mainWindow)
  mainWindow = createWindow()
  if (!capture) {
    scheduleAutoFetch()
    scheduleMonthlyReport()
    updateTray()
  }

  app.on('activate', () => {
    startHidden = false
    if (BrowserWindow.getAllWindows().length === 0) {
      mainWindow = createWindow()
    } else {
      showMainWindow()
    }
  })
})

app.on('before-quit', () => {
  isQuitting = true
})

app.on('window-all-closed', () => {
  // With an active tray the app keeps running in the background.
  if (tray) return
  stopAutoFetch()
  stopMonthlyReport()
  if (process.platform !== 'darwin') {
    app.quit()
  }
})
