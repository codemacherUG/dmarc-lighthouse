import { app, nativeTheme, safeStorage } from 'electron'
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
import { normalizeTheme, type AppTheme } from '../shared/theme'
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
  /** @deprecated stripped on load */
  authorizedSenders?: string[]
}

interface StoredGlobal {
  autoFetchMinutes?: number
  notifyOnFail?: boolean
  passRateAlertThreshold?: number
  notifyNewSource?: boolean
  ignoredSources?: string
  /** @deprecated stripped on load */
  authorizedSenders?: string[]
  runInTray?: boolean
  openAtLogin?: boolean
  language?: AppLocale
  theme?: AppTheme
  oauthGoogleClientId?: string
  oauthMicrosoftClientId?: string
  enrichmentEnabled?: boolean
  geoIpOnlineFallback?: boolean
  /** @deprecated plaintext; migrated to maxmindLicenseKeyEncrypted on load/save */
  maxmindLicenseKey?: string
  maxmindLicenseKeyEncrypted?: string
  dnsblEnabled?: boolean
  cloudRangesEnabled?: boolean
  rdapEnabled?: boolean
  /** @deprecated migrated to hideMailboxNoise */
  hideGoogleNoise?: boolean
  hideMailboxNoise?: boolean
  pdfMonthlyEnabled?: boolean
  pdfMonthlyDir?: string
  /** Written by the scheduler, never by the settings form. */
  pdfMonthlyLastRun?: string
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
  runInTray: true,
  openAtLogin: true,
  language: 'de',
  theme: 'auto',
  oauthGoogleClientId: '',
  oauthMicrosoftClientId: '',
  enrichmentEnabled: true,
  geoIpOnlineFallback: true,
  maxmindLicenseKey: '',
  hasMaxmindLicenseKey: false,
  dnsblEnabled: true,
  cloudRangesEnabled: true,
  rdapEnabled: true,
  hideMailboxNoise: false,
  pdfMonthlyEnabled: false,
  pdfMonthlyDir: '',
  pdfMonthlyLastRun: ''
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
  writeFileSync(settingsPath(), JSON.stringify(stored, null, 2), {
    encoding: 'utf8',
    mode: 0o600
  })
}

/** Migrate plaintext MaxMind key to safeStorage; returns whether settings were rewritten. */
function migrateMaxmindLicenseKey(stored: StoredSettingsV2): boolean {
  const plaintext = stored.global.maxmindLicenseKey?.trim()
  if (!plaintext || stored.global.maxmindLicenseKeyEncrypted) {
    if (plaintext && stored.global.maxmindLicenseKeyEncrypted) {
      delete stored.global.maxmindLicenseKey
      return true
    }
    return false
  }
  try {
    stored.global.maxmindLicenseKeyEncrypted = encryptSecret(plaintext)
    delete stored.global.maxmindLicenseKey
    return true
  } catch {
    return false
  }
}

/** Decrypted MaxMind license key for main-process use only. */
export function getMaxmindLicenseKey(): string {
  const stored = readStored()
  if (migrateMaxmindLicenseKey(stored)) writeStored(stored)
  if (stored.global.maxmindLicenseKeyEncrypted) {
    return decryptSecret(stored.global.maxmindLicenseKeyEncrypted)
  }
  return (stored.global.maxmindLicenseKey ?? '').trim()
}

function encryptSecret(value: string): string {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error(t('main.passwordUnavailable'))
  }
  return safeStorage.encryptString(value).toString('base64')
}

function tryDecryptSecret(encrypted: string): { ok: true; value: string } | { ok: false } {
  if (!safeStorage.isEncryptionAvailable()) return { ok: false }
  try {
    return { ok: true, value: safeStorage.decryptString(Buffer.from(encrypted, 'base64')) }
  } catch {
    return { ok: false }
  }
}

function decryptSecret(encrypted?: string): string {
  if (!encrypted) return ''
  const result = tryDecryptSecret(encrypted)
  return result.ok ? result.value : ''
}

const SECRET_FIELDS = [
  'passwordEncrypted',
  'refreshTokenEncrypted',
  'accessTokenEncrypted'
] as const

const GLOBAL_SECRET_ACCOUNT_ID = '__global__'

export function hasEncryptedSecrets(): boolean {
  const stored = readStored()
  if (stored.global.maxmindLicenseKeyEncrypted || stored.global.maxmindLicenseKey?.trim()) {
    return true
  }
  return stored.accounts.some((a) => SECRET_FIELDS.some((f) => Boolean(a[f])))
}

export function secretsDecryptable(): boolean {
  if (!safeStorage.isEncryptionAvailable()) return !hasEncryptedSecrets()
  const stored = readStored()
  if (stored.global.maxmindLicenseKeyEncrypted) {
    if (!tryDecryptSecret(stored.global.maxmindLicenseKeyEncrypted).ok) return false
  }
  for (const a of stored.accounts) {
    for (const field of SECRET_FIELDS) {
      const encrypted = a[field]
      if (!encrypted) continue
      if (!tryDecryptSecret(encrypted).ok) return false
    }
  }
  return true
}

export function exportSecretsForMigration(): {
  accountId: string
  password?: string
  refreshToken?: string
  accessToken?: string
  accessTokenExpiresAt?: number
  maxmindLicenseKey?: string
}[] {
  const stored = readStored()
  if (migrateMaxmindLicenseKey(stored)) writeStored(stored)
  const out: {
    accountId: string
    password?: string
    refreshToken?: string
    accessToken?: string
    accessTokenExpiresAt?: number
    maxmindLicenseKey?: string
  }[] = []
  for (const a of stored.accounts) {
    const row: (typeof out)[number] = { accountId: a.id }
    if (a.passwordEncrypted) {
      const r = tryDecryptSecret(a.passwordEncrypted)
      if (r.ok) row.password = r.value
    }
    if (a.refreshTokenEncrypted) {
      const r = tryDecryptSecret(a.refreshTokenEncrypted)
      if (r.ok) row.refreshToken = r.value
    }
    if (a.accessTokenEncrypted) {
      const r = tryDecryptSecret(a.accessTokenEncrypted)
      if (r.ok) row.accessToken = r.value
    }
    if (a.accessTokenExpiresAt != null) row.accessTokenExpiresAt = a.accessTokenExpiresAt
    if (row.password || row.refreshToken || row.accessToken) out.push(row)
  }
  if (stored.global.maxmindLicenseKeyEncrypted) {
    const r = tryDecryptSecret(stored.global.maxmindLicenseKeyEncrypted)
    if (r.ok && r.value) {
      out.push({ accountId: GLOBAL_SECRET_ACCOUNT_ID, maxmindLicenseKey: r.value })
    }
  }
  return out
}

export function importSecretsFromMigration(
  secrets: {
    accountId: string
    password?: string
    refreshToken?: string
    accessToken?: string
    accessTokenExpiresAt?: number
    maxmindLicenseKey?: string
  }[]
): void {
  const stored = readStored()
  const byId = new Map(secrets.map((s) => [s.accountId, s]))
  for (const account of stored.accounts) {
    const snap = byId.get(account.id)
    if (!snap) continue
    if (snap.password != null && snap.password !== '') {
      account.passwordEncrypted = encryptSecret(snap.password)
    }
    if (snap.refreshToken != null && snap.refreshToken !== '') {
      account.refreshTokenEncrypted = encryptSecret(snap.refreshToken)
    }
    if (snap.accessToken != null && snap.accessToken !== '') {
      account.accessTokenEncrypted = encryptSecret(snap.accessToken)
    }
    if (snap.accessTokenExpiresAt != null) {
      account.accessTokenExpiresAt = snap.accessTokenExpiresAt
    }
  }
  const globalSnap = byId.get(GLOBAL_SECRET_ACCOUNT_ID)
  if (globalSnap?.maxmindLicenseKey) {
    stored.global.maxmindLicenseKeyEncrypted = encryptSecret(globalSnap.maxmindLicenseKey)
    delete stored.global.maxmindLicenseKey
  }
  writeStored(stored)
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

/** Strip deprecated authorizedSenders from global settings and accounts. */
function stripLegacyAuthorizedSenders(stored: StoredSettingsV2): boolean {
  let dirty = false
  if ('authorizedSenders' in stored.global) {
    delete stored.global.authorizedSenders
    dirty = true
  }
  for (const account of stored.accounts) {
    if ('authorizedSenders' in account) {
      delete account.authorizedSenders
      dirty = true
    }
  }
  return dirty
}

function toPublicGlobal(g: StoredGlobal): GlobalSettings {
  const language = g.language ? normalizeLocale(g.language) : detectSystemLocale(app.getLocale())
  return {
    autoFetchMinutes: normalizeMinutes(g.autoFetchMinutes ?? GLOBAL_DEFAULTS.autoFetchMinutes),
    notifyOnFail: g.notifyOnFail ?? GLOBAL_DEFAULTS.notifyOnFail,
    passRateAlertThreshold: normalizeThreshold(g.passRateAlertThreshold),
    notifyNewSource: Boolean(g.notifyNewSource),
    ignoredSources: g.ignoredSources ?? '',
    runInTray: g.runInTray ?? GLOBAL_DEFAULTS.runInTray,
    openAtLogin: g.openAtLogin ?? GLOBAL_DEFAULTS.openAtLogin,
    language,
    theme: normalizeTheme(g.theme),
    oauthGoogleClientId:
      g.oauthGoogleClientId?.trim() || process.env.DMARC_GOOGLE_CLIENT_ID?.trim() || '',
    oauthMicrosoftClientId:
      g.oauthMicrosoftClientId?.trim() || process.env.DMARC_MS_CLIENT_ID?.trim() || '',
    enrichmentEnabled: g.enrichmentEnabled ?? GLOBAL_DEFAULTS.enrichmentEnabled,
    geoIpOnlineFallback: g.geoIpOnlineFallback ?? GLOBAL_DEFAULTS.geoIpOnlineFallback,
    maxmindLicenseKey: '',
    hasMaxmindLicenseKey: Boolean(g.maxmindLicenseKeyEncrypted || g.maxmindLicenseKey?.trim()),
    dnsblEnabled: g.dnsblEnabled ?? GLOBAL_DEFAULTS.dnsblEnabled,
    cloudRangesEnabled: g.cloudRangesEnabled ?? GLOBAL_DEFAULTS.cloudRangesEnabled,
    rdapEnabled: g.rdapEnabled ?? GLOBAL_DEFAULTS.rdapEnabled,
    hideMailboxNoise: Boolean(g.hideMailboxNoise ?? g.hideGoogleNoise),
    pdfMonthlyEnabled: Boolean(g.pdfMonthlyEnabled),
    pdfMonthlyDir: (g.pdfMonthlyDir ?? '').trim(),
    pdfMonthlyLastRun: g.pdfMonthlyLastRun ?? ''
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
  let dirty = migrateMaxmindLicenseKey(stored)
  if (stripLegacyAuthorizedSenders(stored)) dirty = true
  if (dirty) writeStored(stored)
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
  migrateMaxmindLicenseKey(stored)
  let maxmindLicenseKeyEncrypted = stored.global.maxmindLicenseKeyEncrypted
  const newKey = String(input.maxmindLicenseKey ?? '').trim()
  if (newKey) {
    maxmindLicenseKeyEncrypted = encryptSecret(newKey)
  }
  stored.global = {
    autoFetchMinutes: normalizeMinutes(input.autoFetchMinutes),
    notifyOnFail: Boolean(input.notifyOnFail),
    passRateAlertThreshold: normalizeThreshold(input.passRateAlertThreshold),
    notifyNewSource: Boolean(input.notifyNewSource),
    ignoredSources: input.ignoredSources ?? '',
    runInTray: Boolean(input.runInTray),
    openAtLogin: Boolean(input.openAtLogin),
    language: normalizeLocale(input.language),
    theme: normalizeTheme(input.theme),
    oauthGoogleClientId: String(input.oauthGoogleClientId ?? '').trim(),
    oauthMicrosoftClientId: String(input.oauthMicrosoftClientId ?? '').trim(),
    enrichmentEnabled: input.enrichmentEnabled !== false,
    geoIpOnlineFallback: Boolean(input.geoIpOnlineFallback),
    maxmindLicenseKeyEncrypted,
    dnsblEnabled: input.dnsblEnabled !== false,
    cloudRangesEnabled: input.cloudRangesEnabled !== false,
    rdapEnabled: input.rdapEnabled !== false,
    hideMailboxNoise: Boolean(input.hideMailboxNoise),
    pdfMonthlyEnabled: Boolean(input.pdfMonthlyEnabled),
    pdfMonthlyDir: String(input.pdfMonthlyDir ?? '').trim(),
    // Owned by the scheduler: the form round-trips a display value only.
    pdfMonthlyLastRun: stored.global.pdfMonthlyLastRun ?? ''
  }
  writeStored(stored)
  return loadSettings()
}

/** Remember that the monthly report ran, so it happens once per month. */
export function setMonthlyReportRun(iso: string): void {
  const stored = readStored()
  stored.global.pdfMonthlyLastRun = iso
  writeStored(stored)
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

/** Apply Electron/Chromium color scheme so `prefers-color-scheme` matches the setting. */
export function applyNativeTheme(theme?: AppTheme): void {
  const value = theme ?? loadSettings().global.theme
  nativeTheme.themeSource = value === 'light' || value === 'dark' ? value : 'system'
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
