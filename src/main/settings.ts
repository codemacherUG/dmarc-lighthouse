import { app, safeStorage } from 'electron'
import { existsSync, readFileSync, writeFileSync } from 'fs'
import { join } from 'path'
import type { ImapConnectionInput, ProviderPreset, SavedSettingsPublic } from '../shared/types'
import { PROVIDER_PRESETS } from '../shared/types'

interface StoredSettings {
  provider: ProviderPreset
  host: string
  port: number
  secure: boolean
  user: string
  mailbox: string
  subjectFilter: string
  passwordEncrypted?: string
  autoFetchMinutes?: number
  notifyOnFail?: boolean
  markSeenAfterFetch?: boolean
}

const DEFAULTS: SavedSettingsPublic = {
  provider: 'custom',
  host: '',
  port: 993,
  secure: true,
  user: '',
  mailbox: 'INBOX',
  subjectFilter: 'Report Domain',
  hasPassword: false,
  autoFetchMinutes: 0,
  notifyOnFail: true,
  markSeenAfterFetch: false
}

function settingsPath(): string {
  return join(app.getPath('userData'), 'settings.json')
}

function readStored(): StoredSettings | null {
  const path = settingsPath()
  if (!existsSync(path)) return null
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as StoredSettings
  } catch {
    return null
  }
}

function decryptPassword(encrypted?: string): string {
  if (!encrypted) return ''
  if (!safeStorage.isEncryptionAvailable()) return ''
  try {
    return safeStorage.decryptString(Buffer.from(encrypted, 'base64'))
  } catch {
    return ''
  }
}

function normalizeMinutes(value: unknown): number {
  const n = typeof value === 'number' ? value : Number(value)
  if (!Number.isFinite(n) || n < 0) return 0
  return Math.min(24 * 60, Math.round(n))
}

export function loadPublicSettings(): SavedSettingsPublic {
  const stored = readStored()
  if (!stored) return { ...DEFAULTS }
  return {
    provider: stored.provider ?? DEFAULTS.provider,
    host: stored.host ?? DEFAULTS.host,
    port: stored.port ?? DEFAULTS.port,
    secure: stored.secure ?? DEFAULTS.secure,
    user: stored.user ?? DEFAULTS.user,
    mailbox: stored.mailbox || DEFAULTS.mailbox,
    subjectFilter: stored.subjectFilter ?? DEFAULTS.subjectFilter,
    hasPassword: Boolean(stored.passwordEncrypted),
    autoFetchMinutes: normalizeMinutes(stored.autoFetchMinutes ?? DEFAULTS.autoFetchMinutes),
    notifyOnFail: stored.notifyOnFail ?? DEFAULTS.notifyOnFail,
    markSeenAfterFetch: stored.markSeenAfterFetch ?? DEFAULTS.markSeenAfterFetch
  }
}

export function saveSettings(input: ImapConnectionInput): SavedSettingsPublic {
  const previous = readStored()
  let passwordEncrypted = previous?.passwordEncrypted

  if (input.password) {
    if (!safeStorage.isEncryptionAvailable()) {
      throw new Error('Passwortspeicherung ist auf diesem System nicht verfügbar.')
    }
    passwordEncrypted = safeStorage.encryptString(input.password).toString('base64')
  }

  const stored: StoredSettings = {
    provider: input.provider,
    host: input.host.trim(),
    port: input.port,
    secure: input.secure,
    user: input.user.trim(),
    mailbox: input.mailbox.trim() || 'INBOX',
    subjectFilter: input.subjectFilter,
    passwordEncrypted,
    autoFetchMinutes: normalizeMinutes(input.autoFetchMinutes),
    notifyOnFail: Boolean(input.notifyOnFail),
    markSeenAfterFetch: Boolean(input.markSeenAfterFetch)
  }

  writeFileSync(settingsPath(), JSON.stringify(stored, null, 2), 'utf8')
  return loadPublicSettings()
}

/** Resolve connection settings, filling password from store when the UI sends an empty one. */
export function resolveConnection(input: ImapConnectionInput): ImapConnectionInput {
  const stored = readStored()
  const password = input.password || decryptPassword(stored?.passwordEncrypted)
  if (!password) {
    throw new Error('Kein Passwort angegeben und keines gespeichert.')
  }

  const preset = PROVIDER_PRESETS[input.provider]
  const host = input.host.trim() || preset.host
  if (!host) {
    throw new Error('IMAP-Host fehlt.')
  }
  if (!input.user.trim()) {
    throw new Error('Benutzer fehlt.')
  }

  const pub = loadPublicSettings()

  return {
    provider: input.provider,
    host,
    port: input.port || preset.port,
    secure: input.secure,
    user: input.user.trim(),
    password,
    mailbox: input.mailbox.trim() || 'INBOX',
    subjectFilter: input.subjectFilter,
    autoFetchMinutes: normalizeMinutes(input.autoFetchMinutes ?? pub.autoFetchMinutes),
    notifyOnFail: input.notifyOnFail ?? pub.notifyOnFail,
    markSeenAfterFetch: input.markSeenAfterFetch ?? pub.markSeenAfterFetch
  }
}

/** Build connection from saved settings only (for Abruf aus dem Hauptfenster). */
export function resolveSavedConnection(): ImapConnectionInput {
  const pub = loadPublicSettings()
  return resolveConnection({
    ...pub,
    password: ''
  })
}
