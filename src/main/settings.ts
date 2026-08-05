import { app, safeStorage } from 'electron'
import { randomUUID } from 'crypto'
import { existsSync, readFileSync, writeFileSync } from 'fs'
import { join } from 'path'
import type {
  AccountPublic,
  AccountSettingsInput,
  AuthMode,
  GlobalSettings,
  ImapConnectionInput,
  OAuthProvider,
  ProviderPreset,
  SettingsPublic
} from '../shared/types'
import { PROVIDER_PRESETS } from '../shared/types'
import { resolveAccountLabel, suggestAccountName } from '../shared/account'
import { detectSystemLocale, normalizeLocale, setLocale, t } from '../shared/i18n'
import type { AppLocale } from '../shared/i18n'
import {
  authorizeInteractive,
  oauthProviderForAccount,
  refreshAccessToken,
  type OAuthClientConfig,
  type OAuthTokens
} from './oauth'
import { applyLinuxOpenAtLogin } from './autostart'

interface StoredAccount {
  id: string
  name?: string
  provider: ProviderPreset
  authMode?: AuthMode
  host: string
  port: number
  secure: boolean
  user: string
  mailbox: string
  /** Optional destination folder; empty = leave messages in place. */
  archiveMailbox?: string
  subjectFilter: string
  passwordEncrypted?: string
  refreshTokenEncrypted?: string
  accessTokenEncrypted?: string
  accessTokenExpiresAt?: number
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
  oauthGoogleClientId?: string
  oauthMicrosoftClientId?: string
  enrichmentEnabled?: boolean
  geoIpOnlineFallback?: boolean
  maxmindLicenseKey?: string
  dnsblEnabled?: boolean
  cloudRangesEnabled?: boolean
  rdapEnabled?: boolean
  hideGoogleNoise?: boolean
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
  language: 'de',
  oauthGoogleClientId: '',
  oauthMicrosoftClientId: '',
  enrichmentEnabled: true,
  geoIpOnlineFallback: false,
  maxmindLicenseKey: '',
  dnsblEnabled: true,
  cloudRangesEnabled: true,
  rdapEnabled: true,
  hideGoogleNoise: false
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
        authMode: 'password',
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

function encryptSecret(value: string): string {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error(t('main.passwordUnavailable'))
  }
  return safeStorage.encryptString(value).toString('base64')
}

function decryptSecret(encrypted?: string): string {
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

function normalizeAuthMode(value: unknown): AuthMode {
  return value === 'oauth' ? 'oauth' : 'password'
}

function toPublicAccount(a: StoredAccount): AccountPublic {
  const user = a.user ?? ''
  const host = a.host ?? ''
  const name = (a.name ?? '').trim()
  const authMode = normalizeAuthMode(a.authMode)
  return {
    id: a.id,
    name,
    label: resolveAccountLabel({ name, user, host }),
    suggestedName: suggestAccountName(user, host),
    provider: a.provider ?? 'custom',
    authMode,
    host,
    port: a.port ?? 993,
    secure: a.secure ?? true,
    user,
    mailbox: a.mailbox || 'INBOX',
    archiveMailbox: (a.archiveMailbox ?? '').trim(),
    subjectFilter: a.subjectFilter ?? '',
    hasPassword: Boolean(a.passwordEncrypted),
    hasOAuth: Boolean(a.refreshTokenEncrypted),
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
    language,
    oauthGoogleClientId:
      g.oauthGoogleClientId?.trim() || process.env.DMARC_GOOGLE_CLIENT_ID?.trim() || '',
    oauthMicrosoftClientId:
      g.oauthMicrosoftClientId?.trim() || process.env.DMARC_MS_CLIENT_ID?.trim() || '',
    enrichmentEnabled: g.enrichmentEnabled ?? GLOBAL_DEFAULTS.enrichmentEnabled,
    geoIpOnlineFallback: Boolean(g.geoIpOnlineFallback),
    maxmindLicenseKey: g.maxmindLicenseKey?.trim() ?? '',
    dnsblEnabled: g.dnsblEnabled ?? GLOBAL_DEFAULTS.dnsblEnabled,
    cloudRangesEnabled: g.cloudRangesEnabled ?? GLOBAL_DEFAULTS.cloudRangesEnabled,
    rdapEnabled: g.rdapEnabled ?? GLOBAL_DEFAULTS.rdapEnabled,
    hideGoogleNoise: Boolean(g.hideGoogleNoise)
  }
}

export function getOAuthClientConfig(global?: GlobalSettings): OAuthClientConfig {
  const g = global ?? loadSettings().global
  return {
    googleClientId: g.oauthGoogleClientId || process.env.DMARC_GOOGLE_CLIENT_ID || '',
    microsoftClientId: g.oauthMicrosoftClientId || process.env.DMARC_MS_CLIENT_ID || ''
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
  const authMode = normalizeAuthMode(input.authMode)

  let passwordEncrypted = existing?.passwordEncrypted
  if (authMode === 'password' && input.password) {
    passwordEncrypted = encryptSecret(input.password)
  }
  if (authMode === 'oauth') {
    // Keep password cleared when switching to OAuth unless already empty.
    if (!existing || existing.authMode !== 'oauth') {
      passwordEncrypted = undefined
    }
  }

  const account: StoredAccount = {
    id: existing?.id ?? randomUUID(),
    name: String(input.name ?? '').trim(),
    provider: input.provider,
    authMode,
    host: input.host.trim(),
    port: input.port,
    secure: input.secure,
    user: input.user.trim(),
    mailbox: input.mailbox.trim() || 'INBOX',
    archiveMailbox: (input.archiveMailbox ?? '').trim(),
    subjectFilter: input.subjectFilter,
    passwordEncrypted: authMode === 'password' ? passwordEncrypted : undefined,
    refreshTokenEncrypted: authMode === 'oauth' ? existing?.refreshTokenEncrypted : undefined,
    accessTokenEncrypted: authMode === 'oauth' ? existing?.accessTokenEncrypted : undefined,
    accessTokenExpiresAt: authMode === 'oauth' ? existing?.accessTokenExpiresAt : undefined,
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

function persistOAuthTokens(accountId: string, tokens: OAuthTokens): void {
  const stored = readStored()
  stored.accounts = stored.accounts.map((a) => {
    if (a.id !== accountId) return a
    return {
      ...a,
      authMode: 'oauth',
      user: tokens.email || a.user,
      refreshTokenEncrypted: encryptSecret(tokens.refreshToken),
      accessTokenEncrypted: encryptSecret(tokens.accessToken),
      accessTokenExpiresAt: tokens.expiresAt,
      passwordEncrypted: undefined
    }
  })
  writeStored(stored)
}

export async function beginOAuthLogin(accountId: string): Promise<SettingsPublic> {
  const stored = readStored()
  const account = stored.accounts.find((a) => a.id === accountId)
  if (!account) throw new Error(t('main.noAccount'))
  const oauthProvider = oauthProviderForAccount(account.provider)
  if (!oauthProvider) throw new Error(t('oauth.providerUnsupported'))

  const tokens = await authorizeInteractive(oauthProvider, getOAuthClientConfig())
  const preset = PROVIDER_PRESETS[account.provider] ?? PROVIDER_PRESETS.custom
  stored.accounts = stored.accounts.map((a) =>
    a.id === accountId
      ? {
          ...a,
          authMode: 'oauth' as const,
          user: tokens.email || a.user,
          host: a.host?.trim() || preset.host,
          passwordEncrypted: undefined
        }
      : a
  )
  writeStored(stored)
  persistOAuthTokens(accountId, tokens)
  return loadSettings()
}

export function disconnectOAuth(accountId: string): SettingsPublic {
  const stored = readStored()
  stored.accounts = stored.accounts.map((a) =>
    a.id === accountId
      ? {
          ...a,
          refreshTokenEncrypted: undefined,
          accessTokenEncrypted: undefined,
          accessTokenExpiresAt: undefined
        }
      : a
  )
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
    language: normalizeLocale(input.language),
    oauthGoogleClientId: String(input.oauthGoogleClientId ?? '').trim(),
    oauthMicrosoftClientId: String(input.oauthMicrosoftClientId ?? '').trim(),
    enrichmentEnabled: input.enrichmentEnabled !== false,
    geoIpOnlineFallback: Boolean(input.geoIpOnlineFallback),
    maxmindLicenseKey: String(input.maxmindLicenseKey ?? '').trim(),
    dnsblEnabled: input.dnsblEnabled !== false,
    cloudRangesEnabled: input.cloudRangesEnabled !== false,
    rdapEnabled: input.rdapEnabled !== false,
    hideGoogleNoise: Boolean(input.hideGoogleNoise)
  }
  writeStored(stored)
  return loadSettings()
}

function baseConnection(
  account: StoredAccount
): Omit<ImapConnectionInput, 'authMode' | 'password' | 'accessToken'> {
  const preset = PROVIDER_PRESETS[account.provider ?? 'custom']
  const host = (account.host ?? '').trim() || preset.host
  if (!host) throw new Error(t('main.hostMissing'))
  if (!(account.user ?? '').trim()) throw new Error(t('main.userMissing'))
  return {
    provider: account.provider ?? 'custom',
    host,
    port: account.port || preset.port,
    secure: account.secure ?? true,
    user: account.user.trim(),
    mailbox: (account.mailbox ?? '').trim() || 'INBOX',
    archiveMailbox: (account.archiveMailbox ?? '').trim(),
    subjectFilter: account.subjectFilter ?? '',
    markSeenAfterFetch: Boolean(account.markSeenAfterFetch)
  }
}

async function resolveOAuthAccessToken(account: StoredAccount): Promise<string> {
  const oauthProvider = oauthProviderForAccount(account.provider) as OAuthProvider | null
  if (!oauthProvider) throw new Error(t('oauth.providerUnsupported'))
  const refreshToken = decryptSecret(account.refreshTokenEncrypted)
  if (!refreshToken) throw new Error(t('oauth.notConnected'))

  const accessToken = decryptSecret(account.accessTokenEncrypted)
  const expiresAt = account.accessTokenExpiresAt ?? 0
  if (accessToken && expiresAt > Date.now() + 30_000) {
    return accessToken
  }

  const tokens = await refreshAccessToken(
    oauthProvider,
    getOAuthClientConfig(),
    refreshToken,
    account.user
  )
  persistOAuthTokens(account.id, tokens)
  return tokens.accessToken
}

async function toConnection(
  account: StoredAccount,
  passwordFallback = ''
): Promise<ImapConnectionInput> {
  const base = baseConnection(account)
  const authMode = normalizeAuthMode(account.authMode)
  if (authMode === 'oauth') {
    const accessToken = await resolveOAuthAccessToken(account)
    return { ...base, authMode: 'oauth', accessToken }
  }
  const password = passwordFallback || decryptSecret(account.passwordEncrypted)
  if (!password) throw new Error(t('main.passwordMissing'))
  return { ...base, authMode: 'password', password }
}

/** Resolve the connection for a stored account (default: active account). */
export async function resolveAccountConnection(
  accountId?: string | null
): Promise<ImapConnectionInput> {
  const stored = readStored()
  const id = accountId ?? stored.activeAccountId ?? stored.accounts[0]?.id
  const account = stored.accounts.find((a) => a.id === id)
  if (!account) throw new Error(t('main.noAccount'))
  return toConnection(account)
}

/** Resolve a connection from form input; falls back to stored secrets of the same account. */
export async function resolveInputConnection(
  input: AccountSettingsInput
): Promise<ImapConnectionInput> {
  const stored = readStored()
  const existing = input.id ? stored.accounts.find((a) => a.id === input.id) : undefined
  const authMode = normalizeAuthMode(input.authMode ?? existing?.authMode)
  const account: StoredAccount = {
    id: existing?.id ?? 'new',
    name: input.name,
    provider: input.provider,
    authMode,
    host: input.host,
    port: input.port,
    secure: input.secure,
    user: input.user,
    mailbox: input.mailbox,
    archiveMailbox: input.archiveMailbox,
    subjectFilter: input.subjectFilter,
    passwordEncrypted: existing?.passwordEncrypted,
    refreshTokenEncrypted: existing?.refreshTokenEncrypted,
    accessTokenEncrypted: existing?.accessTokenEncrypted,
    accessTokenExpiresAt: existing?.accessTokenExpiresAt,
    markSeenAfterFetch: input.markSeenAfterFetch
  }
  if (authMode === 'oauth') {
    if (!existing?.refreshTokenEncrypted) throw new Error(t('oauth.notConnected'))
    return toConnection(account)
  }
  return toConnection(account, input.password)
}

/** Apply / clear OS login-item (autostart) based on global settings. */
export function applyOpenAtLogin(settings?: GlobalSettings): void {
  const global = settings ?? loadSettings().global
  const openAtLogin = Boolean(global.openAtLogin)
  const openAsHidden = openAtLogin && Boolean(global.runInTray)
  if (process.platform === 'linux') {
    try {
      applyLinuxOpenAtLogin(openAtLogin, openAsHidden)
    } catch (err) {
      console.warn('[autostart] Failed to update XDG autostart entry:', err)
    }
    return
  }
  try {
    app.setLoginItemSettings({
      openAtLogin,
      openAsHidden,
      args: openAsHidden ? ['--hidden'] : []
    })
  } catch (err) {
    console.warn('[autostart] Failed to update login item settings:', err)
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
