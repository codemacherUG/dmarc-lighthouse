import { BrowserWindow, ipcMain } from 'electron'
import { is } from '@electron-toolkit/utils'
import electronUpdater, { type ProgressInfo, type UpdateDownloadedEvent } from 'electron-updater'
import type { UpdateStatusPayload } from '../shared/types'
import { t } from '../shared/i18n'
import { verifyDownloadedUpdate } from './update-manifest'
import { describeUpdateError } from './update-error'

// CommonJS interop — see electron-builder#7976
const { autoUpdater } = electronUpdater

let getMainWindow: (() => BrowserWindow | null) | null = null
let started = false
/** Set after download + external manifest verification succeeds. */
let verifiedUpdate: { version: string } | null = null
/** Prevents overlapping downloadUpdate() calls after the user confirms. */
let downloadInProgress = false
/** True while the automatic startup check runs: connectivity errors stay out of the banner. */
let backgroundCheck = false

/** Delays before the automatic check is repeated after a connectivity error. */
const BACKGROUND_RETRY_DELAYS_MS = [30_000, 120_000, 600_000]

function send(payload: UpdateStatusPayload): void {
  const win = getMainWindow?.()
  win?.webContents.send('update:status', payload)
}

/** Readable message without the stack trace / feed dump electron-updater puts into `message`. */
function errorMessage(err: unknown): string {
  const info = describeUpdateError(err)
  return info.transient
    ? t('updater.networkError', { code: info.code ?? info.detail })
    : info.detail
}

function sendError(err: unknown): void {
  const info = describeUpdateError(err)
  const message = errorMessage(err)
  // Offline / network just changed during the automatic check: no red banner, only the status line.
  send({ status: 'error', message, ...(backgroundCheck && info.transient ? { silent: true } : {}) })
}

/** Automatic check after startup; retries quietly while the network is not usable yet. */
function runBackgroundCheck(attempt = 0): void {
  backgroundCheck = true
  void autoUpdater
    .checkForUpdates()
    .catch((err: unknown) => {
      // The 'error' event has already reported it (emitted before the promise rejects).
      const delay = BACKGROUND_RETRY_DELAYS_MS[attempt]
      if (describeUpdateError(err).transient && delay != null) {
        setTimeout(() => runBackgroundCheck(attempt + 1), delay)
      }
    })
    .finally(() => {
      backgroundCheck = false
    })
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
    backgroundCheck = false
    try {
      const result = await autoUpdater.checkForUpdates()
      return {
        ok: true,
        message: result?.updateInfo
          ? t('updater.releaseInfo', { version: result.updateInfo.version })
          : t('updater.started')
      }
    } catch (err) {
      sendError(err)
      return { ok: false, message: errorMessage(err) }
    }
  })

  ipcMain.handle('update:download', async () => {
    if (is.dev) return { ok: false, message: t('updater.devDownload') }
    if (downloadInProgress) return { ok: true, message: t('updater.downloadStarted') }
    downloadInProgress = true
    try {
      await autoUpdater.downloadUpdate()
      return { ok: true, message: t('updater.downloadStarted') }
    } catch (err) {
      downloadInProgress = false
      sendError(err)
      return { ok: false, message: errorMessage(err) }
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

  autoUpdater.autoDownload = false
  // Enabled only after external manifest verification succeeds.
  autoUpdater.autoInstallOnAppQuit = false
  // When isSilent=false, quitAndInstall uses this flag (not the 2nd argument).
  autoUpdater.autoRunAppAfterInstall = true
  autoUpdater.allowDowngrade = false
  autoUpdater.disableWebInstaller = true
  // GitHub latest*.yml checksums + Ed25519 manifest on apps.codemacher.de (see update-manifest.ts).
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
    if (downloadInProgress) return
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
    downloadInProgress = false
    autoUpdater.autoInstallOnAppQuit = false
    sendError(err)
  })

  // Kurze Verzögerung, damit das Fenster erst laden kann
  setTimeout(() => runBackgroundCheck(), 4_000)
}
