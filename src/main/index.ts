import { app, shell, BrowserWindow, ipcMain } from 'electron'
import { join } from 'path'
import { electronApp, optimizer, is } from '@electron-toolkit/utils'
import icon from '../../resources/icon.png?asset'
import type { ImapConnectionInput } from '../shared/types'
import { fetchAndAnalyze, testConnection } from './imap'
import { loadPublicSettings, resolveConnection, resolveSavedConnection, saveSettings } from './settings'

// Stabiler Start unter eingeschränkten Linux-/Container-Umgebungen
app.disableHardwareAcceleration()
app.commandLine.appendSwitch('disable-gpu')
if (process.platform === 'linux') {
  app.commandLine.appendSwitch('no-sandbox')
}

function createWindow(): BrowserWindow {
  const mainWindow = new BrowserWindow({
    width: 1180,
    height: 820,
    minWidth: 900,
    minHeight: 640,
    show: false,
    autoHideMenuBar: true,
    title: 'DMARC Viewer',
    ...(process.platform === 'linux' ? { icon } : {}),
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      sandbox: false,
      contextIsolation: true,
      nodeIntegration: false
    }
  })

  mainWindow.on('ready-to-show', () => {
    mainWindow.show()
  })

  mainWindow.webContents.setWindowOpenHandler((details) => {
    shell.openExternal(details.url)
    return { action: 'deny' }
  })

  if (is.dev && process.env['ELECTRON_RENDERER_URL']) {
    mainWindow.loadURL(process.env['ELECTRON_RENDERER_URL'])
  } else {
    mainWindow.loadFile(join(__dirname, '../renderer/index.html'))
  }

  return mainWindow
}

function registerIpc(getWindow: () => BrowserWindow | null): void {
  ipcMain.handle('settings:load', () => loadPublicSettings())

  ipcMain.handle('settings:save', (_event, input: ImapConnectionInput) => {
    return saveSettings(input)
  })

  ipcMain.handle('imap:test', async (_event, input: ImapConnectionInput) => {
    const settings = resolveConnection(input)
    return testConnection(settings)
  })

  ipcMain.handle('imap:fetchAndAnalyze', async (_event, input: ImapConnectionInput) => {
    const settings = resolveConnection(input)
    const win = getWindow()
    return fetchAndAnalyze(settings, (progress) => {
      win?.webContents.send('imap:progress', progress)
    })
  })

  ipcMain.handle('imap:fetchSaved', async () => {
    const settings = resolveSavedConnection()
    const win = getWindow()
    return fetchAndAnalyze(settings, (progress) => {
      win?.webContents.send('imap:progress', progress)
    })
  })
}

app.whenReady().then(() => {
  electronApp.setAppUserModelId('com.dmarcviewer.app')

  app.on('browser-window-created', (_, window) => {
    optimizer.watchWindowShortcuts(window)
  })

  let mainWindow: BrowserWindow | null = null
  registerIpc(() => mainWindow)
  mainWindow = createWindow()

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      mainWindow = createWindow()
    }
  })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit()
  }
})
