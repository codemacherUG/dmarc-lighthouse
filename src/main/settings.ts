import { app, safeStorage } from 'electron'
import { randomUUID } from 'crypto'
import { existsSync, readFileSync, writeFileSync } from 'fs'
import { join } from 'path'
import type {
  AccountPublic,
  AccountSettingsInput,
  GlobalSettings,
  ImapConnectionInput,
  ProviderPreset,
  SettingsPublic
} from '../shared/types'
import { PROVIDER_PRESETS } from '../shared/types'
import { resolveAccountLabel, suggestAccountName } from '../shared/account'
import { detectSystemLocale, normalizeLocale, setLocale, t } from '../shared/i18n'
import type { AppLocale } from '../shared/i18n'

interface StoredAccount {
  id: string
  name?: string
  provider: ProviderPreset
  host: string
  port: number
  secure: boolean
  user: string
  mailbox: string
  subjectFilter: string
  passwordEncrypted?: string
  markSeenAfterFetch?: boolean
}

interface StoredGlobal {
  autoFetchMinutes?: number
  notifyOnFail?: boolean
  passRateAlertThreshold?: number
  notifyNewSource?: boolean
  ignoredSources?: string
  runInTray?: boolean
  openAtLogin?: boolean
  language?: AppLocale
}

interface StoredSettingsV2 {
  version: 2
  activeAccountId: string | null
  accounts: StoredAccount[]
  global: StoredGlobal
}

/** Pre-multi-account file layout (no `version` field). */
interface StoredSettingsV1 {
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

const GLOBAL_DEFAULTS: GlobalSettings = {
  autoFetchMinutes: 0,
  notifyOnFail: true,
  passRateAlertThreshold: 0,
  notifyNewSource: false,
  ignoredSources: '',
  runInTray: false,
  openAtLogin: false,
  language: 'de'
}

function settingsPath(): string {
  return join(app.getPath('userData'), 'settings.json')
}

function migrateV1(v1: StoredSettingsV1): StoredSettingsV2 {
  const hasAccount = Boolean(v1.user || v1.host || v1.passwordEncrypted)
  const account: StoredAccount | null = hasAccount
    ? {
        id: randomUUID(),
        provider: v1.provider ?? 'custom',
        host: v1.host ?? '',
        port: v1.port ?? 993,
        secure: v1.secure ?? true,
        user: v1.user ?? '',
        mailbox: v1.mailbox || 'INBOX',
        subjectFilter: v1.subjectFilter ?? 'Report Domain',
        passwordEncrypted: v1.passwordEncrypted,
        markSeenAfterFetch: Boolean(v1.markSeenAfterFetch)
      }
    : null
  return {
    version: 2,
    activeAccountId: account?.id ?? null,
    accounts: account ? [account] : [],
    global: {
      ...GLOBAL_DEFAULTS,
      autoFetchMinutes: normalizeMinutes(v1.autoFetchMinutes),
      notifyOnFail: v1.notifyOnFail ?? true
    }
  }
}

function readStored(): StoredSettingsV2 {
  const path = settingsPath()
  const empty: StoredSettingsV2 = {
    version: 2,
    activeAccountId: null,
    accounts: [],
    global: { ...GLOBAL_DEFAULTS }
  }
  if (!existsSync(path)) return empty
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as
      StoredSettingsV2 | StoredSettingsV1 | null
    if (!parsed || typeof parsed !== 'object') return empty
    if ('version' in parsed && parsed.version === 2) {
      return {
        version: 2,
        activeAccountId: parsed.activeAccountId ?? null,
        accounts: Array.isArray(parsed.accounts) ? parsed.accounts : [],
        global: parsed.global ?? {}
      }
    }
    const migrated = migrateV1(parsed as StoredSettingsV1)
    writeStored(migrated)
    return migrated
  } catch {
    return empty
  }
}

function writeStored(stored: StoredSettingsV2): void {
  writeFileSync(settingsPath(), JSON.stringify(stored, null, 2), 'utf8')
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

function normalizeThreshold(value: unknown): number {
  const n = typeof value === 'number' ? value : Number(value)
  if (!Number.isFinite(n) || n <= 0) return 0
  return Math.min(100, Math.round(n * 10) / 10)
}

function toPublicAccount(a: StoredAccount): AccountPublic {
  const user = a.user ?? ''
  const host = a.host ?? ''
  const name = (a.name ?? '').trim()
  return {
    id: a.id,
    name,
    label: resolveAccountLabel({ name, user, host }),
    suggestedName: suggestAccountName(user, host),
    provider: a.provider ?? 'custom',
    host,
    port: a.port ?? 993,
    secure: a.secure ?? true,
    user,
    mailbox: a.mailbox || 'INBOX',
    subjectFilter: a.subjectFilter ?? '',
    hasPassword: Boolean(a.passwordEncrypted),
    markSeenAfterFetch: Boolean(a.markSeenAfterFetch)
  }
}

function toPublicGlobal(g: StoredGlobal): GlobalSettings {
  const language = g.language ? normalizeLocale(g.language) : detectSystemLocale(app.getLocale())
  return {
    autoFetchMinutes: normalizeMinutes(g.autoFetchMinutes ?? GLOBAL_DEFAULTS.autoFetchMinutes),
    notifyOnFail: g.notifyOnFail ?? GLOBAL_DEFAULTS.notifyOnFail,
    passRateAlertThreshold: normalizeThreshold(g.passRateAlertThreshold),
    notifyNewSource: Boolean(g.notifyNewSource),
    ignoredSources: g.ignoredSources ?? '',
    runInTray: Boolean(g.runInTray),
    openAtLogin: Boolean(g.openAtLogin),
    language
  }
}

export function loadSettings(): SettingsPublic {
  const stored = readStored()
  const settings = {
    accounts: stored.accounts.map(toPublicAccount),
    activeAccountId:
      stored.activeAccountId && stored.accounts.some((a) => a.id === stored.activeAccountId)
        ? stored.activeAccountId
        : (stored.accounts[0]?.id ?? null),
    global: toPublicGlobal(stored.global)
  }
  setLocale(settings.global.language)
  return settings
}

export function saveAccount(input: AccountSettingsInput): SettingsPublic {
  const stored = readStored()
  const existing = input.id ? stored.accounts.find((a) => a.id === input.id) : undefined

  let passwordEncrypted = existing?.passwordEncrypted
  if (input.password) {
    if (!safeStorage.isEncryptionAvailable()) {
      throw new Error(t('main.passwordUnavailable'))
    }
    passwordEncrypted = safeStorage.encryptString(input.password).toString('base64')
  }

  const account: StoredAccount = {
    id: existing?.id ?? randomUUID(),
    name: String(input.name ?? '').trim(),
    provider: input.provider,
    host: input.host.trim(),
    port: input.port,
    secure: input.secure,
    user: input.user.trim(),
    mailbox: input.mailbox.trim() || 'INBOX',
    subjectFilter: input.subjectFilter,
    passwordEncrypted,
    markSeenAfterFetch: Boolean(input.markSeenAfterFetch)
  }

  if (existing) {
    stored.accounts = stored.accounts.map((a) => (a.id === account.id ? account : a))
  } else {
    stored.accounts.push(account)
  }
  if (!stored.activeAccountId) {
    stored.activeAccountId = account.id
  }
  writeStored(stored)
  return loadSettings()
}

export function deleteAccount(id: string): SettingsPublic {
  const stored = readStored()
  stored.accounts = stored.accounts.filter((a) => a.id !== id)
  if (stored.activeAccountId === id) {
    stored.activeAccountId = stored.accounts[0]?.id ?? null
  }
  writeStored(stored)
  return loadSettings()
}

export function setActiveAccount(id: string): SettingsPublic {
  const stored = readStored()
  if (stored.accounts.some((a) => a.id === id)) {
    stored.activeAccountId = id
    writeStored(stored)
  }
  return loadSettings()
}

export function saveGlobalSettings(input: GlobalSettings): SettingsPublic {
  const stored = readStored()
  stored.global = {
    autoFetchMinutes: normalizeMinutes(input.autoFetchMinutes),
    notifyOnFail: Boolean(input.notifyOnFail),
    passRateAlertThreshold: normalizeThreshold(input.passRateAlertThreshold),
    notifyNewSource: Boolean(input.notifyNewSource),
    ignoredSources: input.ignoredSources ?? '',
    runInTray: Boolean(input.runInTray),
    openAtLogin: Boolean(input.openAtLogin),
    language: normalizeLocale(input.language)
  }
  writeStored(stored)
  return loadSettings()
}

function toConnection(account: StoredAccount, password: string): ImapConnectionInput {
  const preset = PROVIDER_PRESETS[account.provider ?? 'custom']
  const host = (account.host ?? '').trim() || preset.host
  if (!host) throw new Error(t('main.hostMissing'))
  if (!(account.user ?? '').trim()) throw new Error(t('main.userMissing'))
  if (!password) throw new Error(t('main.passwordMissing'))
  return {
    provider: account.provider ?? 'custom',
    host,
    port: account.port || preset.port,
    secure: account.secure ?? true,
    user: account.user.trim(),
    password,
    mailbox: (account.mailbox ?? '').trim() || 'INBOX',
    subjectFilter: account.subjectFilter ?? '',
    markSeenAfterFetch: Boolean(account.markSeenAfterFetch)
  }
}

/** Resolve the connection for a stored account (default: active account). */
export function resolveAccountConnection(accountId?: string | null): ImapConnectionInput {
  const stored = readStored()
  const id = accountId ?? stored.activeAccountId ?? stored.accounts[0]?.id
  const account = stored.accounts.find((a) => a.id === id)
  if (!account) throw new Error(t('main.noAccount'))
  return toConnection(account, decryptPassword(account.passwordEncrypted))
}

/** Resolve a connection from form input; falls back to the stored password of the same account. */
export function resolveInputConnection(input: AccountSettingsInput): ImapConnectionInput {
  const stored = readStored()
  const existing = input.id ? stored.accounts.find((a) => a.id === input.id) : undefined
  const password = input.password || decryptPassword(existing?.passwordEncrypted)
  return toConnection(
    {
      id: existing?.id ?? 'new',
      name: input.name,
      provider: input.provider,
      host: input.host,
      port: input.port,
      secure: input.secure,
      user: input.user,
      mailbox: input.mailbox,
      subjectFilter: input.subjectFilter,
      markSeenAfterFetch: input.markSeenAfterFetch
    },
    password
  )
}

/** Apply / clear OS login-item (autostart) based on global settings. */
export function applyOpenAtLogin(settings?: GlobalSettings): void {
  const global = settings ?? loadSettings().global
  const openAtLogin = Boolean(global.openAtLogin)
  const openAsHidden = openAtLogin && Boolean(global.runInTray)
  try {
    app.setLoginItemSettings({
      openAtLogin,
      openAsHidden,
      args: openAsHidden ? ['--hidden'] : []
    })
  } catch {
    // Some environments (e.g. certain Linux packaging modes) may not support this.
  }
}

/** Parse the ignore list into matchers: exact IPs or prefixes ending with `*`. */
export function parseIgnoredSources(text: string): Array<{ exact?: string; prefix?: string }> {
  return text
    .split(/[\n,;]+/)
    .map((s) => s.trim())
    .filter(Boolean)
    .map((entry) =>
      entry.endsWith('*') ? { prefix: entry.slice(0, -1) } : { exact: entry.toLowerCase() }
    )
}

export function isIgnoredSource(
  ip: string,
  matchers: Array<{ exact?: string; prefix?: string }>
): boolean {
  const normalized = ip.trim().toLowerCase()
  return matchers.some((m) =>
    m.exact != null ? normalized === m.exact : normalized.startsWith((m.prefix ?? '').toLowerCase())
  )
}
