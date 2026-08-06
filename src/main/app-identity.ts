import { app } from 'electron'
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'fs'
import { join } from 'path'

/**
 * safeStorage keys are bound to app.getName() (esp. macOS Keychain / Linux libsecret).
 * Renaming the app for branding must NOT change this value, or encrypted passwords
 * become undecryptable. Prefer the historical package name forever.
 */
export const SAFE_STORAGE_APP_NAME = 'dmarcviewer'

/** Briefly used in v1.0.11 after the Lighthouse rename — migrate away from this. */
export const LEGACY_SAFE_STORAGE_APP_NAME = 'dmarc-lighthouse'

const MARKER_FILENAME = 'de.codemacher.dmarcviewer.safe-storage-name'
const MIGRATE_FILENAME = 'de.codemacher.dmarcviewer.safe-storage-migrate.json'
const TRIED_FILENAME = 'de.codemacher.dmarcviewer.safe-storage-tried'

export const USER_DATA_CANDIDATES = [
  'dmarcviewer',
  'DMARC Viewer',
  'dmarc-lighthouse',
  'DMARC Lighthouse'
] as const

export function safeStorageMarkerPath(appData = app.getPath('appData')): string {
  return join(appData, MARKER_FILENAME)
}

export function safeStorageMigratePath(appData = app.getPath('appData')): string {
  return join(appData, MIGRATE_FILENAME)
}

export function safeStorageTriedPath(appData = app.getPath('appData')): string {
  return join(appData, TRIED_FILENAME)
}

export function resolveSafeStorageAppName(opts: {
  appData?: string
  markerContents?: string | null
  migratePending?: boolean
}): string {
  if (opts.migratePending) return SAFE_STORAGE_APP_NAME
  const raw = opts.markerContents?.trim()
  if (raw === SAFE_STORAGE_APP_NAME || raw === LEGACY_SAFE_STORAGE_APP_NAME) return raw
  return SAFE_STORAGE_APP_NAME
}

export function resolveUserDataDir(opts: {
  appData: string
  candidates?: readonly string[]
  hasSettings?: (dir: string) => boolean
  dirExists?: (dir: string) => boolean
}): string | null {
  const names = opts.candidates ?? USER_DATA_CANDIDATES
  const hasSettings = opts.hasSettings ?? ((dir: string) => existsSync(join(dir, 'settings.json')))
  const dirExists = opts.dirExists ?? ((dir: string) => existsSync(dir))
  for (const name of names) {
    const dir = join(opts.appData, name)
    if (hasSettings(dir)) return dir
  }
  for (const name of names) {
    const dir = join(opts.appData, name)
    if (dirExists(dir)) return dir
  }
  return null
}

/** Call before app.whenReady(): userData path + safeStorage-bound app name. */
export function applyAppIdentityBeforeReady(): void {
  const appData = app.getPath('appData')
  const userData = resolveUserDataDir({ appData })
  if (userData) app.setPath('userData', userData)

  const markerPath = safeStorageMarkerPath(appData)
  const migratePath = safeStorageMigratePath(appData)
  let markerContents: string | null = null
  if (existsSync(markerPath)) {
    try {
      markerContents = readFileSync(markerPath, 'utf8')
    } catch {
      markerContents = null
    }
  }

  const name = resolveSafeStorageAppName({
    markerContents,
    migratePending: existsSync(migratePath)
  })
  app.setName(name)
}

export interface SafeStorageSecretSnapshot {
  accountId: string
  password?: string
  refreshToken?: string
  accessToken?: string
  accessTokenExpiresAt?: number
  /** Present on the `__global__` sentinel row when a MaxMind key is stored. */
  maxmindLicenseKey?: string
}

function writeMarker(name: string): void {
  writeFileSync(safeStorageMarkerPath(), `${name}\n`, { encoding: 'utf8', mode: 0o600 })
}

function readTriedNames(): Set<string> {
  const path = safeStorageTriedPath()
  if (!existsSync(path)) return new Set()
  try {
    return new Set(
      readFileSync(path, 'utf8')
        .split('\n')
        .map((l) => l.trim())
        .filter(Boolean)
    )
  } catch {
    return new Set()
  }
}

function rememberTriedName(name: string): void {
  const tried = readTriedNames()
  tried.add(name)
  writeFileSync(safeStorageTriedPath(), [...tried].join('\n') + '\n', {
    encoding: 'utf8',
    mode: 0o600
  })
}

function clearTriedNames(): void {
  try {
    unlinkSync(safeStorageTriedPath())
  } catch {
    /* ignore */
  }
}

/**
 * After ready: ensure encrypted secrets decrypt under the current app name.
 * May relaunch once to try the alternate name or finish migration to the stable name.
 * Returns false when the caller should abort (relaunch scheduled).
 */
export function ensureSafeStorageIdentity(hooks: {
  hasEncryptedSecrets: () => boolean
  secretsDecryptable: () => boolean
  exportSecrets: () => SafeStorageSecretSnapshot[]
  importSecrets: (secrets: SafeStorageSecretSnapshot[]) => void
  relaunch: () => void
}): boolean {
  const migratePath = safeStorageMigratePath()

  if (existsSync(migratePath)) {
    try {
      const raw = readFileSync(migratePath, 'utf8')
      const secrets = JSON.parse(raw) as SafeStorageSecretSnapshot[]
      hooks.importSecrets(secrets)
      writeMarker(SAFE_STORAGE_APP_NAME)
      clearTriedNames()
    } finally {
      try {
        unlinkSync(migratePath)
      } catch {
        /* ignore */
      }
    }
    return true
  }

  if (!hooks.hasEncryptedSecrets()) {
    writeMarker(SAFE_STORAGE_APP_NAME)
    clearTriedNames()
    if (app.getName() !== SAFE_STORAGE_APP_NAME) {
      app.setName(SAFE_STORAGE_APP_NAME)
    }
    return true
  }

  if (hooks.secretsDecryptable()) {
    const current = app.getName()
    if (current === SAFE_STORAGE_APP_NAME) {
      writeMarker(SAFE_STORAGE_APP_NAME)
      clearTriedNames()
      return true
    }

    // Decryptable under the v1.0.11 name — move ciphertext to the stable name.
    const secrets = hooks.exportSecrets()
    const dir = app.getPath('appData')
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
    writeFileSync(migratePath, JSON.stringify(secrets), { encoding: 'utf8', mode: 0o600 })
    writeMarker(SAFE_STORAGE_APP_NAME)
    hooks.relaunch()
    return false
  }

  // Wrong key for this process — try the other historical name once.
  const current = app.getName()
  rememberTriedName(current)
  const alternate =
    current === SAFE_STORAGE_APP_NAME ? LEGACY_SAFE_STORAGE_APP_NAME : SAFE_STORAGE_APP_NAME
  const tried = readTriedNames()
  if (tried.has(alternate)) {
    // Both names failed (e.g. keyring wiped) — continue; user must re-enter secrets.
    return true
  }
  writeMarker(alternate)
  hooks.relaunch()
  return false
}
