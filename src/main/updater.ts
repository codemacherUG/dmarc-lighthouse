import { BrowserWindow, ipcMain } from 'electron'
import { is } from '@electron-toolkit/utils'
import electronUpdater, { type ProgressInfo, type UpdateInfo } from 'electron-updater'
import type { UpdateStatusPayload } from '../shared/types'
import { t } from '../shared/i18n'

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

  ipcMain.handle('update:check', async () => {
    if (is.dev) {
      send({ status: 'not-available', version: '' })
      return { ok: false, message: t('updater.devDisabled') }
    }
    try {
      const result = await autoUpdater.checkForUpdates()
      return {
        ok: true,
        message: result?.updateInfo
          ? t('updater.releaseInfo', { version: result.updateInfo.version })
          : t('updater.started')
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      send({ status: 'error', message })
      return { ok: false, message }
    }
  })

  ipcMain.handle('update:install', () => {
    if (is.dev) return { ok: false, message: t('updater.devInstall') }
    // isSilent=false, isForceRunAfter=true
    autoUpdater.quitAndInstall(false, true)
    return { ok: true, message: t('updater.installing') }
  })

  if (is.dev) return

  autoUpdater.autoDownload = true
  autoUpdater.autoInstallOnAppQuit = true
  // When isSilent=false, quitAndInstall uses this flag (not the 2nd argument).
  autoUpdater.autoRunAppAfterInstall = true
  autoUpdater.allowDowngrade = false
  // Checksums from latest*.yml are verified by electron-updater. Platform code-signing
  // (CSC_LINK / Apple notarize) must be enabled in CI for signature checks to apply.

  // Versioned AppImage filenames: updater writes a new path and emits this event.
  autoUpdater.on('appimage-filename-updated', (newPath: string) => {
    if (typeof newPath === 'string' && newPath.trim()) {
      process.env.APPIMAGE = newPath
    }
  })

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
