import { app, BrowserWindow, ipcMain } from 'electron'
import { is } from '@electron-toolkit/utils'
import electronUpdater, { type ProgressInfo, type UpdateInfo } from 'electron-updater'
import type { UpdateStatusPayload } from '../shared/types'

// CommonJS interop — see electron-builder#7976
const { autoUpdater } = electronUpdater

let getMainWindow: (() => BrowserWindow | null) | null = null
let started = false

function send(payload: UpdateStatusPayload): void {
  const win = getMainWindow?.()
  win?.webContents.send('update:status', payload)
}

function versionOf(info: UpdateInfo | null | undefined): string {
  return info?.version ?? ''
}

export function setupAutoUpdater(getWindow: () => BrowserWindow | null): void {
  if (started) return
  started = true
  getMainWindow = getWindow

  ipcMain.handle('app:getVersion', () => app.getVersion())

  ipcMain.handle('update:check', async () => {
    if (is.dev) {
      send({ status: 'not-available', version: '' })
      return { ok: false, message: 'Updates sind im Dev-Modus deaktiviert.' }
    }
    try {
      const result = await autoUpdater.checkForUpdates()
      return {
        ok: true,
        message: result?.updateInfo
          ? `Aktuelle Release-Info: ${result.updateInfo.version}`
          : 'Update-Prüfung gestartet.'
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      send({ status: 'error', message })
      return { ok: false, message }
    }
  })

  ipcMain.handle('update:install', () => {
    if (is.dev) return { ok: false, message: 'Im Dev-Modus nicht verfügbar.' }
    // isSilent=false, isForceRunAfter=true
    autoUpdater.quitAndInstall(false, true)
    return { ok: true, message: 'Installiere Update…' }
  })

  if (is.dev) return

  autoUpdater.autoDownload = true
  autoUpdater.autoInstallOnAppQuit = true

  autoUpdater.on('checking-for-update', () => {
    send({ status: 'checking' })
  })

  autoUpdater.on('update-available', (info: UpdateInfo) => {
    send({ status: 'available', version: versionOf(info) })
  })

  autoUpdater.on('update-not-available', (info: UpdateInfo) => {
    send({ status: 'not-available', version: versionOf(info) })
  })

  autoUpdater.on('download-progress', (progress: ProgressInfo) => {
    send({
      status: 'downloading',
      percent: progress.percent,
      transferred: progress.transferred,
      total: progress.total
    })
  })

  autoUpdater.on('update-downloaded', (info: UpdateInfo) => {
    send({ status: 'downloaded', version: versionOf(info) })
  })

  autoUpdater.on('error', (err: Error) => {
    send({ status: 'error', message: err?.message || String(err) })
  })

  // Kurze Verzögerung, damit das Fenster erst laden kann
  setTimeout(() => {
    void autoUpdater.checkForUpdates().catch((err: unknown) => {
      const message = err instanceof Error ? err.message : String(err)
      send({ status: 'error', message })
    })
  }, 4_000)
}
