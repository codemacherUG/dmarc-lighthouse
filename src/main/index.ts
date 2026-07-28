import { app, shell, BrowserWindow, ipcMain, dialog, Notification } from 'electron'
import { join, basename } from 'path'
import { readFileSync, writeFileSync } from 'fs'
import { electronApp, optimizer, is } from '@electron-toolkit/utils'
import { createAppIcon } from './icon'
import type { AnalyzeResult, ImapConnectionInput, SavedSettingsPublic } from '../shared/types'
import { parseLocalBuffers } from './analyze'
import { accountKeyFor, clearCache, loadCachedReports } from './cache'
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
  loadPublicSettings,
  resolveConnection,
  resolveSavedConnection,
  saveSettings
} from './settings'
import { setupAutoUpdater } from './updater'

app.disableHardwareAcceleration()
app.commandLine.appendSwitch('disable-gpu')
if (process.platform === 'linux') {
  app.commandLine.appendSwitch('no-sandbox')
}

let mainWindow: BrowserWindow | null = null
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

function notifyFailIncrease(prevFailing: number, result: AnalyzeResult): void {
  const settings = loadPublicSettings()
  if (!settings.notifyOnFail) return
  if (result.aggregate.failing <= prevFailing) return
  if (!Notification.isSupported()) return

  const delta = result.aggregate.failing - prevFailing
  const n = new Notification({
    title: 'DMARC Viewer',
    body: `Neue Failures: +${delta} Nachrichten (gesamt ${result.aggregate.failing} fail).`
  })
  n.show()
}

async function runSavedFetch(): Promise<AnalyzeResult> {
  if (fetchInFlight) {
    throw new Error('Abruf läuft bereits.')
  }
  fetchInFlight = true
  try {
    const settings = resolveSavedConnection()
    const prevFailing = previousFailingTotal(settings)
    const result = await fetchAndAnalyze(settings, (progress) => {
      mainWindow?.webContents.send('imap:progress', progress)
    })
    notifyFailIncrease(prevFailing, result)
    mainWindow?.webContents.send('imap:result', result)
    return result
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

function scheduleAutoFetch(settings?: SavedSettingsPublic): void {
  stopAutoFetch()
  const s = settings ?? loadPublicSettings()
  const minutes = s.autoFetchMinutes
  if (!minutes || minutes <= 0 || !s.hasPassword || !s.user) return

  autoFetchTimer = setInterval(() => {
    void runSavedFetch().catch((err) => {
      mainWindow?.webContents.send('imap:progress', {
        phase: 'error',
        processed: 0,
        total: 0,
        parsed: 0,
        skipped: 0,
        message: err instanceof Error ? err.message : String(err)
      })
    })
  }, minutes * 60_000)
}

function registerIpc(): void {
  ipcMain.handle('settings:load', () => loadPublicSettings())

  ipcMain.handle('settings:save', (_event, input: ImapConnectionInput) => {
    const saved = saveSettings(input)
    scheduleAutoFetch(saved)
    return saved
  })

  ipcMain.handle('imap:test', async (_event, input: ImapConnectionInput) => {
    const settings = resolveConnection(input)
    return testConnection(settings)
  })

  ipcMain.handle('imap:fetchAndAnalyze', async (_event, input: ImapConnectionInput) => {
    const settings = resolveConnection(input)
    const prevFailing = previousFailingTotal(settings)
    const result = await fetchAndAnalyze(settings, (progress) => {
      mainWindow?.webContents.send('imap:progress', progress)
    })
    notifyFailIncrease(prevFailing, result)
    return result
  })

  ipcMain.handle('imap:fetchSaved', async () => runSavedFetch())

  ipcMain.handle('cache:load', () => {
    try {
      const settings = resolveSavedConnection()
      return loadCachedAnalyzeResult(settings)
    } catch {
      return null
    }
  })

  ipcMain.handle('cache:clear', () => {
    const pub = loadPublicSettings()
    if (!pub.user) return { ok: false, message: 'Keine Zugangsdaten.' }
    const host = pub.host || ''
    const key = accountKeyFor(pub.user, host, pub.mailbox)
    clearCache(key)
    return { ok: true, message: 'Cache geleert.' }
  })

  ipcMain.handle('cache:meta', () => {
    try {
      const settings = resolveSavedConnection()
      const key = accountKeyFor(settings.user, settings.host, settings.mailbox)
      return loadCachedReports(key).meta
    } catch {
      return null
    }
  })

  ipcMain.handle('ip:resolve', async (_event, ips: string[]) => resolveIps(ips ?? []))

  ipcMain.handle('dns:check', async (_event, domain: string) => checkDomainDns(domain))

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

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      mainWindow = createWindow()
    }
  })
})

app.on('window-all-closed', () => {
  stopAutoFetch()
  if (process.platform !== 'darwin') {
    app.quit()
  }
})
