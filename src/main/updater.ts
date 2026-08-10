import { BrowserWindow, ipcMain } from 'electron'
import { is } from '@electron-toolkit/utils'
import electronUpdater, { type ProgressInfo, type UpdateDownloadedEvent } from 'electron-updater'
import type { UpdateStatusPayload } from '../shared/types'
import { t } from '../shared/i18n'
import { verifyDownloadedUpdate } from './update-manifest'

// CommonJS interop — see electron-builder#7976
const { autoUpdater } = electronUpdater

let getMainWindow: (() => BrowserWindow | null) | null = null
let started = false
/** Set after download + external manifest verification succeeds. */
let verifiedUpdate: { version: string } | null = null

function send(payload: UpdateStatusPayload): void {
  const win = getMainWindow?.()
  win?.webContents.send('update:status', payload)
}

function versionOf(info: { version?: string } | null | undefined): string {
  return info?.version ?? ''
}

async function verifyAndMark(info: UpdateDownloadedEvent): Promise<boolean> {
  send({ status: 'verifying', version: versionOf(info) })
  const result = await verifyDownloadedUpdate(info)
  if (!result.ok) {
    verifiedUpdate = null
    autoUpdater.autoInstallOnAppQuit = false
    send({ status: 'error', message: t('updater.verifyFailed', { reason: result.reason }) })
    return false
  }
  verifiedUpdate = { version: info.version }
  autoUpdater.autoInstallOnAppQuit = true
  send({ status: 'downloaded', version: versionOf(info) })
  return true
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
    if (!verifiedUpdate) {
      return { ok: false, message: t('updater.notVerified') }
    }
    // isSilent=false, isForceRunAfter=true
    autoUpdater.quitAndInstall(false, true)
    return { ok: true, message: t('updater.installing') }
  })

  if (is.dev) return

  autoUpdater.autoDownload = true
  // Enabled only after external manifest verification succeeds.
  autoUpdater.autoInstallOnAppQuit = false
  // When isSilent=false, quitAndInstall uses this flag (not the 2nd argument).
  autoUpdater.autoRunAppAfterInstall = true
  autoUpdater.allowDowngrade = false
  autoUpdater.disableWebInstaller = true
  // GitHub latest*.yml checksums + Ed25519 manifest on codemacher.de (see update-manifest.ts).
  // Platform code-signing (CSC_LINK / Apple notarize) remains optional hardening.

  // Versioned AppImage filenames: updater writes a new path and emits this event.
  autoUpdater.on('appimage-filename-updated', (newPath: string) => {
    if (typeof newPath === 'string' && newPath.trim()) {
      process.env.APPIMAGE = newPath
    }
  })

  autoUpdater.on('checking-for-update', () => {
    send({ status: 'checking' })
  })

  autoUpdater.on('update-available', (info) => {
    verifiedUpdate = null
    autoUpdater.autoInstallOnAppQuit = false
    send({ status: 'available', version: versionOf(info) })
  })

  autoUpdater.on('update-not-available', (info) => {
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

  autoUpdater.on('update-downloaded', (info: UpdateDownloadedEvent) => {
    void verifyAndMark(info)
  })

  autoUpdater.on('error', (err: Error) => {
    verifiedUpdate = null
    autoUpdater.autoInstallOnAppQuit = false
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
