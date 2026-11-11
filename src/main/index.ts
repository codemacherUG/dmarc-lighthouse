import { app, BrowserWindow, Menu, nativeTheme, Notification, Tray } from 'electron'
import { join } from 'path'
import { tmpdir } from 'os'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs'
import { electronApp, optimizer, is } from '@electron-toolkit/utils'
import { createAppIcon, createTrayIcon } from './icon'
import { pruneExpiredReports } from './cache'
import { registerIpc } from './ipc'
import {
  configureScheduler,
  runAutoFetchAll,
  scheduleAutoFetch,
  scheduleDnsAutoCheck,
  scheduleMonthlyReport,
  stopAutoFetch,
  stopDnsAutoCheck,
  stopMonthlyReport
} from './scheduler'
import {
  applyNativeTheme,
  applyOpenAtLogin,
  exportSecretsForMigration,
  hasEncryptedSecrets,
  importSecretsFromMigration,
  loadSettings,
  secretsDecryptable
} from './settings'
import { setupAutoUpdater } from './updater'
import { runScreenshotCapture, wantsScreenshotCapture } from './screenshots'
import { t } from '../shared/i18n'
import { applyAppIdentityBeforeReady, ensureSafeStorageIdentity } from './app-identity'
import { fixPackagedExecEnv, relaunchApp } from './relaunch'
import { openExternalSafe } from './open-external'
import { configureDnsEnvironment } from './dns-env'

if (process.platform === 'linux') {
  app.disableHardwareAcceleration()
  app.commandLine.appendSwitch('disable-gpu')
  app.commandLine.appendSwitch('no-sandbox')
  // Avoid Chromium FATAL on /dev/shm shared-memory create (ESRCH) when spawning windows.
  app.commandLine.appendSwitch('disable-dev-shm-usage')
}
if (is.dev) {
  // Native DevTools windows need a real compositor; without one, use a browser instead:
  // open http://localhost:9223 and click "inspect" on the app's page.
  app.commandLine.appendSwitch('remote-debugging-port', '9223')
  // Chromium 111+ drops the CDP connection unless the caller's origin is allow-listed.
  app.commandLine.appendSwitch('remote-allow-origins', '*')
}
configureDnsEnvironment()

let mainWindow: BrowserWindow | null = null
let noticesWindow: BrowserWindow | null = null
let tray: Tray | null = null
let isQuitting = false
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
    // DMARC_DEMO=1 npm run dev loads the demo data (incl. simulated new sending sources)
    // without needing DevTools, whose window some Linux setups never surface.
    if (process.env['DMARC_DEMO']) {
      win.webContents.once('did-finish-load', () => {
        void win.webContents.executeJavaScript(
          "window.__dmarcScreenshot && window.__dmarcScreenshot.prepareDemo('de')"
        )
      })
    }
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

configureScheduler({
  getMainWindow: () => mainWindow,
  notify,
  markTrayAttentionIfHidden
})

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
  if (!capture && settings.global.reportRetentionDays > 0) {
    try {
      pruneExpiredReports(settings.global.reportRetentionDays)
    } catch {
      // Optional startup retention cleanup.
    }
  }
  startHidden = capture ? false : shouldStartHidden()
  if (!capture) applyOpenAtLogin(settings.global)
  applyNativeTheme(settings.global.theme)

  registerIpc({
    getMainWindow: () => mainWindow,
    updateTray,
    openThirdPartyNoticesWindow
  })
  if (!capture) setupAutoUpdater(() => mainWindow)
  mainWindow = createWindow()
  if (!capture) {
    scheduleAutoFetch()
    scheduleMonthlyReport()
    scheduleDnsAutoCheck()
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
  stopDnsAutoCheck()
  if (process.platform !== 'darwin') {
    app.quit()
  }
})
