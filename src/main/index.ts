import { app, shell, BrowserWindow, ipcMain, dialog, Menu, Notification, Tray } from 'electron'
import { join, basename } from 'path'
import { readFileSync, writeFileSync } from 'fs'
import { electronApp, optimizer, is } from '@electron-toolkit/utils'
import { createAppIcon } from './icon'
import type {
  AccountPublic,
  AccountSettingsInput,
  AnalyzeResult,
  GlobalSettings,
  ReportRow
} from '../shared/types'
import { parseLocalBuffers } from './analyze'
import { accountKeyFor, clearCache } from './cache'
import { checkDomainDns } from './dnscheck'
import { exportReportsCsv, exportReportsJson } from './export'
import {
  fetchAndAnalyze,
  loadCachedAnalyzeResult,
  previousFailingTotal,
  testConnection
} from './imap'
import { resolveIps } from './ipinfo'
import {
  deleteAccount,
  isIgnoredSource,
  loadSettings,
  parseIgnoredSources,
  resolveAccountConnection,
  resolveInputConnection,
  saveAccount,
  saveGlobalSettings,
  setActiveAccount
} from './settings'
import { setupAutoUpdater } from './updater'

app.disableHardwareAcceleration()
app.commandLine.appendSwitch('disable-gpu')
if (process.platform === 'linux') {
  app.commandLine.appendSwitch('no-sandbox')
}

let mainWindow: BrowserWindow | null = null
let tray: Tray | null = null
let isQuitting = false
let autoFetchTimer: ReturnType<typeof setInterval> | null = null
let fetchInFlight = false

function createWindow(): BrowserWindow {
  const appIcon = createAppIcon()

  const win = new BrowserWindow({
    width: 1280,
    height: 900,
    minWidth: 960,
    minHeight: 680,
    show: false,
    autoHideMenuBar: true,
    title: 'DMARC Viewer',
    ...(appIcon.isEmpty() ? {} : { icon: appIcon }),
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
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
    win.show()
  })

  win.on('close', (event) => {
    // With tray mode enabled, closing the window keeps the app (and auto-fetch) running.
    if (!isQuitting && loadSettings().global.runInTray) {
      event.preventDefault()
      win.hide()
    }
  })

  win.webContents.setWindowOpenHandler((details) => {
    shell.openExternal(details.url)
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
  if (!mainWindow || mainWindow.isDestroyed()) {
    mainWindow = createWindow()
    return
  }
  if (mainWindow.isMinimized()) mainWindow.restore()
  mainWindow.show()
  mainWindow.focus()
}

function updateTray(): void {
  const wantTray = loadSettings().global.runInTray
  if (wantTray && !tray) {
    const icon = createAppIcon()
    tray = new Tray(icon.isEmpty() ? icon : icon.resize({ width: 22, height: 22 }))
    tray.setToolTip('DMARC Viewer')
    tray.setContextMenu(
      Menu.buildFromTemplate([
        { label: 'DMARC Viewer anzeigen', click: () => showMainWindow() },
        { label: 'Jetzt abrufen', click: () => void runAutoFetchAll() },
        { type: 'separator' },
        {
          label: 'Beenden',
          click: () => {
            isQuitting = true
            app.quit()
          }
        }
      ])
    )
    tray.on('click', () => showMainWindow())
  } else if (!wantTray && tray) {
    tray.destroy()
    tray = null
  }
}

function notify(body: string): void {
  if (!Notification.isSupported()) return
  const n = new Notification({ title: 'DMARC Viewer', body })
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
      `Neue Failures: +${delta} Nachrichten (gesamt ${result.aggregate.failing} fail)${suffix}.`
    )
  }

  if (global.passRateAlertThreshold > 0 && (result.newReports ?? 0) > 0) {
    const rate = passRateLastDays(result.reports, 7)
    if (rate != null && rate < global.passRateAlertThreshold) {
      notify(
        `Pass-Rate der letzten 7 Tage bei ${rate.toFixed(1)}% — unter Schwelle von ${global.passRateAlertThreshold}%${suffix}.`
      )
    }
  }

  if (global.notifyNewSource && result.newSourceIps && result.newSourceIps.length > 0) {
    const matchers = parseIgnoredSources(global.ignoredSources)
    const relevant = result.newSourceIps.filter((ip) => !isIgnoredSource(ip, matchers))
    if (relevant.length > 0) {
      const shown = relevant.slice(0, 3).join(', ')
      const more = relevant.length > 3 ? ` und ${relevant.length - 3} weitere` : ''
      notify(`Neue Quelle erkannt: ${shown}${more}${suffix}.`)
    }
  }
}

async function runSavedFetch(accountId?: string | null): Promise<AnalyzeResult> {
  if (fetchInFlight) {
    throw new Error('Abruf läuft bereits.')
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
  if (!account) throw new Error('Kein IMAP-Konto konfiguriert.')

  const connection = resolveAccountConnection(account.id)
  const prevFailing = previousFailingTotal(connection)
  const result = await fetchAndAnalyze(connection, (progress) => {
    mainWindow?.webContents.send('imap:progress', progress)
  })
  result.accountId = account.id
  runAlerts(account, prevFailing, result)
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
      if (!account.hasPassword || !account.user) continue
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
  const hasAccount = settingsPub.accounts.some((a) => a.hasPassword && a.user)
  if (!minutes || minutes <= 0 || !hasAccount) return

  autoFetchTimer = setInterval(() => {
    void runAutoFetchAll()
  }, minutes * 60_000)
}

function registerIpc(): void {
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
    scheduleAutoFetch()
    updateTray()
    return saved
  })

  ipcMain.handle('imap:test', async (_event, input: AccountSettingsInput) => {
    const connection = resolveInputConnection(input)
    return testConnection(connection)
  })

  ipcMain.handle('imap:fetchSaved', async (_event, accountId?: string | null) =>
    runSavedFetch(accountId)
  )

  ipcMain.handle('cache:load', (_event, accountId?: string | null) => {
    try {
      const connection = resolveAccountConnection(accountId)
      const result = loadCachedAnalyzeResult(connection)
      const settingsPub = loadSettings()
      result.accountId = accountId ?? settingsPub.activeAccountId ?? undefined
      return result
    } catch {
      return null
    }
  })

  ipcMain.handle('cache:clear', (_event, accountId?: string | null) => {
    const settingsPub = loadSettings()
    const id = accountId ?? settingsPub.activeAccountId
    const account = settingsPub.accounts.find((a) => a.id === id)
    if (!account) return { ok: false, message: 'Kein Konto ausgewählt.' }
    clearCache(accountKeyFor(account.user, account.host, account.mailbox))
    return { ok: true, message: 'Cache geleert.' }
  })

  ipcMain.handle('ip:resolve', async (_event, ips: string[]) => resolveIps(ips ?? []))

  ipcMain.handle('dns:check', async (_event, domain: string, selectors?: string[]) =>
    checkDomainDns(domain, selectors ?? [])
  )

  ipcMain.handle('files:open', async () => {
    const openOptions = {
      title: 'DMARC-Reports öffnen',
      properties: ['openFile', 'multiSelections'] as Array<'openFile' | 'multiSelections'>,
      filters: [
        { name: 'DMARC Reports', extensions: ['xml', 'gz', 'zip', 'eml', 'mime'] },
        { name: 'Alle Dateien', extensions: ['*'] }
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
    return parseLocalBuffers(buffers)
  })

  ipcMain.handle('files:parsePaths', async (_event, paths: string[]) => {
    const buffers = (paths ?? []).map((p) => ({
      name: basename(p),
      data: readFileSync(p)
    }))
    return parseLocalBuffers(buffers)
  })

  ipcMain.handle('export:save', async (_event, result: AnalyzeResult, format: 'json' | 'csv') => {
    const defaultPath = format === 'json' ? 'dmarc-reports.json' : 'dmarc-reports.csv'
    const saveOptions = {
      title: 'Export speichern',
      defaultPath,
      filters:
        format === 'json'
          ? [{ name: 'JSON', extensions: ['json'] }]
          : [{ name: 'CSV', extensions: ['csv'] }]
    }
    const save = mainWindow
      ? await dialog.showSaveDialog(mainWindow, saveOptions)
      : await dialog.showSaveDialog(saveOptions)
    if (save.canceled || !save.filePath) return { ok: false, message: 'Abgebrochen.' }

    const content = format === 'json' ? exportReportsJson(result) : exportReportsCsv(result)
    writeFileSync(save.filePath, content, 'utf8')
    return { ok: true, message: `Gespeichert: ${save.filePath}` }
  })
}

app.whenReady().then(() => {
  // Must match linux.desktop StartupWMClass / Icon theme name so the panel
  // associates this window with the AppImage .desktop entry (SVG icon).
  app.setName('dmarcviewer')
  electronApp.setAppUserModelId('de.codemacher.dmarcviewer')

  app.on('browser-window-created', (_, window) => {
    optimizer.watchWindowShortcuts(window)
  })

  registerIpc()
  setupAutoUpdater(() => mainWindow)
  mainWindow = createWindow()
  scheduleAutoFetch()
  updateTray()

  app.on('activate', () => {
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
  if (process.platform !== 'darwin') {
    app.quit()
  }
})
