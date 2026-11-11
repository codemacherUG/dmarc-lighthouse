import { app, type BrowserWindow, dialog, ipcMain } from 'electron'
import { readFileSync, writeFileSync } from 'fs'
import { basename } from 'path'
import { ALL_ACCOUNTS_ID, isAllAccountsId } from '../shared/account'
import { emailInspectPdfFilename } from '../shared/email-inspect-html'
import { t } from '../shared/i18n'
import { monthlyReportFilename } from '../shared/report-period'
import { normalizeTheme } from '../shared/theme'
import type {
  AccountSettingsInput,
  AnalyzeResult,
  AppTheme,
  ConfigBackupPayload,
  DomainDkimSelector,
  EmailInspectResult,
  GlobalSettings,
  ReportRetentionCleanupResult,
  ReportRow,
  SendingServiceInput
} from '../shared/types'
import {
  LOCAL_IMPORT_ACCOUNT_KEY,
  acknowledgePendingSourceIps,
  accountKeyFor,
  clearCache,
  deleteSendingService,
  getDnsHealthCache,
  getDnsHistory,
  getDomainDkimSelectors,
  listAllDomainDkimSelectors,
  listSendingServices,
  pruneExpiredReports,
  recordDnsHistory,
  recordTransportHistory,
  resetKnownSourceIps,
  saveDomainDkimSelectors as persistDomainDkimSelectors,
  upsertDnsHealthCache,
  upsertSendingService
} from './cache'
import { checkBimiDns, checkDomainDns, normalizeDkimSelector } from './dnscheck'
import { buildDomainHealth } from './domainhealth'
import { inspectEmailBuffer, inspectEmailText } from './email-inspect'
import { exportReportZip, exportReportsCsv, exportReportsJson } from './export'
import { downloadGeoLite, getGeoLiteStatus } from './geoip'
import {
  createMailbox,
  listMailboxes,
  loadCachedAnalyzeResult,
  loadCombinedCachedAnalyzeResult,
  testConnection
} from './imap'
import { importLocalFiles, loadLocalImportResult } from './import'
import { clearIpInfoMemoryCache, resolveIps } from './ipinfo'
import { buildEmailInspectPdf, buildPdfReport, domainHealthFromReports } from './pdf-report'
import { lookupRdap } from './rdap'
import {
  allAccountsCacheKeys,
  importTargetAccount,
  runMonthlyReport,
  runSavedFetch,
  scheduleAutoFetch,
  scheduleMonthlyReport
} from './scheduler'
import {
  applyNativeTheme,
  applyOpenAtLogin,
  beginOAuthLogin,
  deleteAccount,
  disconnectOAuth,
  exportSettingsForBackup,
  getMaxmindLicenseKey,
  importSettingsFromBackup,
  loadSettings,
  resolveInputConnection,
  saveAccount,
  saveGlobalSettings,
  setActiveAccount
} from './settings'
import { expandSpf } from './spf-expand'
import { checkTransportSecurity } from './transport'

export interface RegisterIpcHooks {
  getMainWindow: () => BrowserWindow | null
  updateTray: () => void
  openThirdPartyNoticesWindow: () => Promise<{ ok: boolean; message: string }>
}

export function registerIpc(hooks: RegisterIpcHooks): void {
  ipcMain.handle('app:getVersion', () => app.getVersion())

  ipcMain.handle('app:openThirdPartyNotices', async () => {
    try {
      return await hooks.openThirdPartyNoticesWindow()
    } catch (e) {
      return { ok: false, message: e instanceof Error ? e.message : String(e) }
    }
  })

  ipcMain.handle('settings:load', () => loadSettings())

  ipcMain.handle('settings:saveAccount', (_event, input: AccountSettingsInput) => {
    const saved = saveAccount(input)
    scheduleAutoFetch()
    return saved
  })

  ipcMain.handle('settings:deleteAccount', (_event, id: string) => {
    // Drop the account's cache along with the account itself.
    try {
      const account = loadSettings().accounts.find((a) => a.id === id)
      if (account) {
        clearCache(accountKeyFor(account.user, account.host, account.mailbox))
      }
    } catch {
      // Cache-Aufräumen ist optional.
    }
    const saved = deleteAccount(id)
    scheduleAutoFetch()
    return saved
  })

  ipcMain.handle('settings:setActiveAccount', (_event, id: string) => setActiveAccount(id))

  ipcMain.handle('settings:saveGlobal', (_event, input: GlobalSettings) => {
    const saved = saveGlobalSettings(input)
    if (saved.global.reportRetentionDays > 0) {
      pruneExpiredReports(saved.global.reportRetentionDays)
    }
    clearIpInfoMemoryCache()
    applyOpenAtLogin(saved.global)
    applyNativeTheme(saved.global.theme)
    scheduleAutoFetch()
    scheduleMonthlyReport()
    hooks.updateTray()
    return saved
  })

  ipcMain.handle(
    'cache:pruneExpired',
    (_event, retentionDays?: number): ReportRetentionCleanupResult & { message: string } => {
      const days =
        typeof retentionDays === 'number' && Number.isFinite(retentionDays)
          ? Math.max(0, Math.round(retentionDays))
          : loadSettings().global.reportRetentionDays
      const res = pruneExpiredReports(days)
      const total = res.deletedReports + res.deletedForensic + res.deletedTlsRpt
      return {
        ...res,
        message:
          days <= 0
            ? t('settings.retentionDisabledNote')
            : t('settings.retentionPruned', { count: total, days })
      }
    }
  )

  ipcMain.handle('config:export', async () => {
    const date = new Date().toISOString().slice(0, 10)
    const saveOptions = {
      title: t('settings.backupExportTitle'),
      defaultPath: `dmarc-lighthouse-config-${date}.json`,
      filters: [{ name: 'JSON', extensions: ['json'] }]
    }
    const mainWindow = hooks.getMainWindow()
    const save = mainWindow
      ? await dialog.showSaveDialog(mainWindow, saveOptions)
      : await dialog.showSaveDialog(saveOptions)
    if (save.canceled || !save.filePath) return { ok: false, message: t('main.cancelled') }

    const settingsSnap = exportSettingsForBackup()
    const payload: ConfigBackupPayload = {
      format: 'dmarc-lighthouse-config',
      version: 1,
      exportedAt: new Date().toISOString(),
      activeAccountId: settingsSnap.activeAccountId,
      accounts: settingsSnap.accounts,
      global: settingsSnap.global,
      sendingServices: listSendingServices(),
      domainDkimSelectors: listAllDomainDkimSelectors()
    }
    writeFileSync(save.filePath, JSON.stringify(payload, null, 2), 'utf8')
    return { ok: true, message: t('main.saved', { path: save.filePath }) }
  })

  ipcMain.handle('config:import', async () => {
    const openOptions = {
      title: t('settings.backupImportTitle'),
      properties: ['openFile'] as Array<'openFile'>,
      filters: [
        { name: 'JSON', extensions: ['json'] },
        { name: 'Alle Dateien / All files', extensions: ['*'] }
      ]
    }
    const mainWindow = hooks.getMainWindow()
    const picked = mainWindow
      ? await dialog.showOpenDialog(mainWindow, openOptions)
      : await dialog.showOpenDialog(openOptions)
    if (picked.canceled || picked.filePaths.length === 0) {
      return { ok: false, message: t('main.cancelled'), settings: null }
    }
    try {
      const raw = JSON.parse(
        readFileSync(picked.filePaths[0]!, 'utf8')
      ) as Partial<ConfigBackupPayload> | null
      if (!raw || typeof raw !== 'object' || raw.format !== 'dmarc-lighthouse-config') {
        return { ok: false, message: t('settings.backupInvalid'), settings: null }
      }
      const nextSettings = importSettingsFromBackup({
        activeAccountId: raw.activeAccountId,
        accounts: raw.accounts,
        global: raw.global
      })
      if (Array.isArray(raw.sendingServices)) {
        for (const svc of raw.sendingServices) {
          if (!svc || typeof svc !== 'object' || typeof svc.provider !== 'string') continue
          upsertSendingService({
            id: typeof svc.id === 'string' ? svc.id : undefined,
            provider: svc.provider,
            domain: svc.domain ?? null,
            cidr: svc.cidr ?? null,
            asn: typeof svc.asn === 'number' ? svc.asn : null,
            status:
              svc.status === 'known' ||
              svc.status === 'unknown' ||
              svc.status === 'retired' ||
              svc.status === 'investigate'
                ? svc.status
                : 'known',
            note: svc.note ?? null,
            team: svc.team ?? null
          })
        }
      }
      if (raw.domainDkimSelectors && typeof raw.domainDkimSelectors === 'object') {
        for (const [domain, list] of Object.entries(raw.domainDkimSelectors)) {
          if (!domain.trim() || !Array.isArray(list)) continue
          const valid = list
            .map((item) => {
              const sel =
                item && typeof item.selector === 'string'
                  ? normalizeDkimSelector(item.selector)
                  : null
              if (!sel) return null
              return {
                selector: sel,
                enabled: Boolean(item.enabled),
                ...(item.manual === true ? { manual: true } : {})
              }
            })
            .filter((item): item is DomainDkimSelector => Boolean(item))
          if (valid.length > 0) {
            persistDomainDkimSelectors(domain, valid)
          }
        }
      }
      clearIpInfoMemoryCache()
      applyOpenAtLogin(nextSettings.global)
      applyNativeTheme(nextSettings.global.theme)
      scheduleAutoFetch()
      scheduleMonthlyReport()
      hooks.updateTray()
      return {
        ok: true,
        message: t('settings.backupImported', { count: nextSettings.accounts.length }),
        settings: nextSettings
      }
    } catch (err) {
      return {
        ok: false,
        message: err instanceof Error ? err.message : String(err),
        settings: null
      }
    }
  })

  ipcMain.handle('settings:previewTheme', (_event, theme: AppTheme) => {
    applyNativeTheme(normalizeTheme(theme))
  })

  ipcMain.handle('imap:test', async (_event, input: AccountSettingsInput) => {
    const connection = await resolveInputConnection(input)
    return testConnection(connection)
  })

  ipcMain.handle('imap:listMailboxes', async (_event, input: AccountSettingsInput) => {
    const connection = await resolveInputConnection(input)
    return listMailboxes(connection)
  })

  ipcMain.handle(
    'imap:createMailbox',
    async (_event, input: AccountSettingsInput, path: string) => {
      const connection = await resolveInputConnection(input)
      return createMailbox(connection, path ?? '')
    }
  )

  ipcMain.handle('imap:fetchSaved', async (_event, accountId?: string | null) =>
    runSavedFetch(accountId)
  )

  ipcMain.handle('oauth:login', async (_event, accountId: string) => beginOAuthLogin(accountId))

  ipcMain.handle('oauth:disconnect', (_event, accountId: string) => disconnectOAuth(accountId))

  ipcMain.handle('cache:load', async (_event, accountId?: string | null) => {
    try {
      const settingsPub = loadSettings()
      const id = accountId ?? settingsPub.activeAccountId
      if (isAllAccountsId(id)) {
        const result = await loadCombinedCachedAnalyzeResult(allAccountsCacheKeys(settingsPub))
        result.accountId = ALL_ACCOUNTS_ID
        return result
      }
      const account = settingsPub.accounts.find((a) => a.id === id)
      // No usable account yet: show reports that were imported from files.
      if (!account?.user || !account.host) return loadLocalImportResult()
      const result = await loadCachedAnalyzeResult({
        provider: account.provider,
        host: account.host,
        port: account.port,
        secure: account.secure,
        user: account.user,
        authMode: account.authMode,
        mailbox: account.mailbox,
        archiveMailbox: account.archiveMailbox,
        subjectFilter: account.subjectFilter,
        markSeenAfterFetch: account.markSeenAfterFetch
      })
      result.accountId = id ?? undefined
      return result
    } catch {
      return null
    }
  })

  ipcMain.handle('cache:clear', (_event, accountId?: string | null) => {
    const settingsPub = loadSettings()
    const id = accountId ?? settingsPub.activeAccountId
    if (isAllAccountsId(id)) {
      for (const key of allAccountsCacheKeys(settingsPub)) {
        clearCache(key)
      }
      return { ok: true, message: t('main.cacheCleared') }
    }
    const account = settingsPub.accounts.find((a) => a.id === id)
    if (!account) {
      // Without an account the only cached data can come from file imports.
      clearCache(LOCAL_IMPORT_ACCOUNT_KEY)
      return { ok: true, message: t('main.cacheCleared') }
    }
    clearCache(accountKeyFor(account.user, account.host, account.mailbox))
    return { ok: true, message: t('main.cacheCleared') }
  })

  ipcMain.handle('cache:resetKnownSources', (_event, accountId?: string | null) => {
    const settingsPub = loadSettings()
    const id = accountId ?? settingsPub.activeAccountId
    if (isAllAccountsId(id)) {
      for (const key of allAccountsCacheKeys(settingsPub)) {
        resetKnownSourceIps(key)
      }
      return { ok: true, message: t('main.knownSourcesReset') }
    }
    const account = settingsPub.accounts.find((a) => a.id === id)
    const key = account
      ? accountKeyFor(account.user, account.host, account.mailbox)
      : LOCAL_IMPORT_ACCOUNT_KEY
    resetKnownSourceIps(key)
    return { ok: true, message: t('main.knownSourcesReset') }
  })

  ipcMain.handle(
    'cache:acknowledgePendingSources',
    (_event, ips?: string[], accountId?: string | null) => {
      const settingsPub = loadSettings()
      const id = accountId ?? settingsPub.activeAccountId
      if (isAllAccountsId(id)) {
        for (const key of allAccountsCacheKeys(settingsPub)) {
          acknowledgePendingSourceIps(key, ips)
        }
        return
      }
      const account = settingsPub.accounts.find((a) => a.id === id)
      const key = account
        ? accountKeyFor(account.user, account.host, account.mailbox)
        : LOCAL_IMPORT_ACCOUNT_KEY
      acknowledgePendingSourceIps(key, ips)
    }
  )

  ipcMain.handle('ip:resolve', async (_event, ips: string[]) => resolveIps(ips ?? []))

  ipcMain.handle('sendingServices:list', () => listSendingServices())

  ipcMain.handle('sendingServices:upsert', (_event, input: SendingServiceInput) =>
    upsertSendingService(input)
  )

  ipcMain.handle('sendingServices:delete', (_event, id: string) => {
    deleteSendingService(id)
    return listSendingServices()
  })

  ipcMain.handle('ip:rdap', async (_event, ip: string) => {
    const settingsPub = loadSettings()
    if (!settingsPub.global.rdapEnabled || !settingsPub.global.enrichmentEnabled) {
      return {
        ip: ip ?? '',
        org: null,
        country: null,
        cidr: null,
        abuseEmail: null,
        rawSummary: null,
        error: t('enrichment.rdapDisabled')
      }
    }
    return lookupRdap(ip ?? '')
  })

  ipcMain.handle('dns:check', async (_event, domain: string, selectors?: string[]) => {
    const result = await checkDomainDns(domain, selectors ?? [])
    recordDnsHistory(result)
    upsertDnsHealthCache(result.domain, result)
    return result
  })

  ipcMain.handle('dns:bimi', async (_event, domain: string, selector?: string) =>
    checkBimiDns(domain ?? '', selector)
  )

  ipcMain.handle('dns:expandSpf', async (_event, domain: string, record?: string | null) =>
    expandSpf(domain ?? '', { record: record ?? null })
  )

  ipcMain.handle('dns:transport', async (_event, domain: string) => {
    const result = await checkTransportSecurity(domain ?? '')
    recordTransportHistory(result)
    return result
  })

  ipcMain.handle('dns:history', (_event, domain: string) => getDnsHistory(domain ?? ''))

  ipcMain.handle('dns:healthBatch', async (_event, reports: ReportRow[]) =>
    buildDomainHealth(Array.isArray(reports) ? reports : [])
  )

  ipcMain.handle('dns:domainDkimSelectors:get', (_event, domain: string) => {
    if (typeof domain !== 'string' || !domain.trim()) {
      throw new Error('A domain is required to load DKIM selector settings')
    }
    return getDomainDkimSelectors(domain)
  })

  ipcMain.handle(
    'dns:domainDkimSelectors:save',
    (_event, domain: string, input: DomainDkimSelector[]) => {
      if (typeof domain !== 'string' || !domain.trim()) {
        throw new Error('A domain is required to save DKIM selector settings')
      }
      if (!Array.isArray(input)) throw new Error('DKIM selector settings must be a list')
      const selectors = input.map((entry) => {
        if (entry == null || typeof entry !== 'object') {
          throw new Error('Each DKIM selector setting must be an object')
        }
        const { selector, enabled, manual } = entry
        const normalized = typeof selector === 'string' ? normalizeDkimSelector(selector) : null
        if (!normalized || typeof enabled !== 'boolean') {
          throw new Error('Each DKIM selector must have a valid selector name and enabled state')
        }
        return { selector: normalized, enabled, ...(manual === true ? { manual: true } : {}) }
      })
      const unique = [...new Map(selectors.map((item) => [item.selector, item])).values()]
      persistDomainDkimSelectors(domain, unique)
      return getDomainDkimSelectors(domain)
    }
  )

  ipcMain.handle('enrichment:geoLiteStatus', () => getGeoLiteStatus())

  ipcMain.handle('enrichment:downloadGeoLite', async (_event, licenseKey?: string) => {
    const typed = typeof licenseKey === 'string' ? licenseKey.trim() : ''
    const key = typed || getMaxmindLicenseKey()
    return downloadGeoLite(key)
  })

  ipcMain.handle('files:open', async (_event, targetAccountId?: string | null) => {
    const openOptions = {
      title: t('main.openReports'),
      properties: ['openFile', 'multiSelections'] as Array<'openFile' | 'multiSelections'>,
      filters: [
        {
          name: 'DMARC / TLS-RPT Reports',
          extensions: ['xml', 'gz', 'zip', 'eml', 'mime', 'json']
        },
        { name: 'Alle Dateien / All files', extensions: ['*'] }
      ]
    }
    const mainWindow = hooks.getMainWindow()
    const result = mainWindow
      ? await dialog.showOpenDialog(mainWindow, openOptions)
      : await dialog.showOpenDialog(openOptions)
    if (result.canceled || result.filePaths.length === 0) return null

    const buffers = result.filePaths.map((p) => ({
      name: basename(p),
      data: readFileSync(p)
    }))
    const imported = await importLocalFiles(buffers, importTargetAccount(targetAccountId))
    if (isAllAccountsId(loadSettings().activeAccountId)) {
      const combined = await loadCombinedCachedAnalyzeResult(allAccountsCacheKeys())
      combined.accountId = ALL_ACCOUNTS_ID
      combined.imported = imported.imported
      combined.skipped = imported.skipped
      combined.errors = imported.errors
      return combined
    }
    return imported
  })

  ipcMain.handle(
    'files:parseBuffers',
    async (
      _event,
      files: Array<{ name?: string; data?: ArrayBuffer | Uint8Array }>,
      targetAccountId?: string | null
    ) => {
      const buffers: Array<{ name: string; data: Buffer }> = []
      for (const [index, f] of (Array.isArray(files) ? files : []).entries()) {
        if (!f?.data) continue
        const rawName = typeof f.name === 'string' && f.name.trim() ? f.name : `file-${index}`
        buffers.push({
          name: basename(rawName),
          data: Buffer.from(f.data instanceof ArrayBuffer ? new Uint8Array(f.data) : f.data)
        })
      }
      const imported = await importLocalFiles(buffers, importTargetAccount(targetAccountId))
      if (isAllAccountsId(loadSettings().activeAccountId)) {
        const combined = await loadCombinedCachedAnalyzeResult(allAccountsCacheKeys())
        combined.accountId = ALL_ACCOUNTS_ID
        combined.imported = imported.imported
        combined.skipped = imported.skipped
        combined.errors = imported.errors
        return combined
      }
      return imported
    }
  )

  ipcMain.handle('email:open', async () => {
    const openOptions = {
      title: t('main.openEmail'),
      properties: ['openFile'] as Array<'openFile'>,
      filters: [
        { name: 'E-Mail', extensions: ['eml', 'emlx', 'msg', 'mime', 'txt'] },
        { name: 'Alle Dateien / All files', extensions: ['*'] }
      ]
    }
    const mainWindow = hooks.getMainWindow()
    const picked = mainWindow
      ? await dialog.showOpenDialog(mainWindow, openOptions)
      : await dialog.showOpenDialog(openOptions)
    if (picked.canceled || picked.filePaths.length === 0) return null
    const filePath = picked.filePaths[0]
    return inspectEmailBuffer(readFileSync(filePath), basename(filePath))
  })

  ipcMain.handle(
    'email:parse',
    async (_event, input: { name?: string; data?: ArrayBuffer | Uint8Array; text?: string }) => {
      if (typeof input?.text === 'string') {
        return inspectEmailText(input.text, input.name?.trim() || 'paste.eml')
      }
      if (!input?.data) return { ok: false, message: t('email.emptyFile') }
      const rawName =
        typeof input.name === 'string' && input.name.trim() ? input.name : 'message.eml'
      const bytes = input.data instanceof ArrayBuffer ? new Uint8Array(input.data) : input.data
      return inspectEmailBuffer(bytes, basename(rawName))
    }
  )

  ipcMain.handle('email:pdf', async (_event, result: EmailInspectResult) => {
    if (!result || typeof result !== 'object' || !Array.isArray(result.checks)) {
      return { ok: false, message: t('email.pdfEmpty') }
    }
    const mainWindow = hooks.getMainWindow()
    const pdf = await buildEmailInspectPdf(result, { host: mainWindow })
    const saveOptions = {
      title: t('main.saveEmailPdf'),
      defaultPath: emailInspectPdfFilename(
        typeof result.fileName === 'string' ? result.fileName : 'message'
      ),
      filters: [{ name: 'PDF', extensions: ['pdf'] }]
    }
    const save = mainWindow
      ? await dialog.showSaveDialog(mainWindow, saveOptions)
      : await dialog.showSaveDialog(saveOptions)
    if (save.canceled || !save.filePath) return { ok: false, message: t('main.cancelled') }
    writeFileSync(save.filePath, pdf)
    return { ok: true, message: t('main.saved', { path: save.filePath }) }
  })

  ipcMain.handle('export:save', async (_event, result: AnalyzeResult, format: 'json' | 'csv') => {
    const defaultPath = format === 'json' ? 'dmarc-reports.json' : 'dmarc-reports.csv'
    const saveOptions = {
      title: t('main.saveExport'),
      defaultPath,
      filters:
        format === 'json'
          ? [{ name: 'JSON', extensions: ['json'] }]
          : [{ name: 'CSV', extensions: ['csv'] }]
    }
    const mainWindow = hooks.getMainWindow()
    const save = mainWindow
      ? await dialog.showSaveDialog(mainWindow, saveOptions)
      : await dialog.showSaveDialog(saveOptions)
    if (save.canceled || !save.filePath) return { ok: false, message: t('main.cancelled') }

    const content = format === 'json' ? exportReportsJson(result) : exportReportsCsv(result)
    writeFileSync(save.filePath, content, 'utf8')
    return { ok: true, message: t('main.saved', { path: save.filePath }) }
  })

  ipcMain.handle('export:reportZip', async (_event, report: ReportRow) => {
    if (!report?.reportId) return { ok: false, message: t('main.exportReportMissing') }
    const { filename, data } = exportReportZip(report)
    const saveOptions = {
      title: t('main.saveReportZip'),
      defaultPath: filename,
      filters: [{ name: 'ZIP', extensions: ['zip'] }]
    }
    const mainWindow = hooks.getMainWindow()
    const save = mainWindow
      ? await dialog.showSaveDialog(mainWindow, saveOptions)
      : await dialog.showSaveDialog(saveOptions)
    if (save.canceled || !save.filePath) return { ok: false, message: t('main.cancelled') }
    writeFileSync(save.filePath, data)
    return { ok: true, message: t('main.saved', { path: save.filePath }) }
  })

  ipcMain.handle(
    'report:pdf',
    async (_event, result: AnalyzeResult, options: { domain?: string | null } = {}) => {
      const domain = options.domain?.trim() || null
      const mainWindow = hooks.getMainWindow()
      const pdf = await buildPdfReport(result, {
        domain,
        domains: domainHealthFromReports(result.reports, (d) => getDnsHealthCache(d)),
        host: mainWindow
      })
      const saveOptions = {
        title: t('main.savePdf'),
        defaultPath: monthlyReportFilename(domain, new Date().toISOString().slice(0, 10)),
        filters: [{ name: 'PDF', extensions: ['pdf'] }]
      }
      const save = mainWindow
        ? await dialog.showSaveDialog(mainWindow, saveOptions)
        : await dialog.showSaveDialog(saveOptions)
      if (save.canceled || !save.filePath) return { ok: false, message: t('main.cancelled') }
      writeFileSync(save.filePath, pdf)
      return { ok: true, message: t('main.saved', { path: save.filePath }) }
    }
  )

  ipcMain.handle('report:chooseDir', async () => {
    const options = { properties: ['openDirectory' as const, 'createDirectory' as const] }
    const mainWindow = hooks.getMainWindow()
    const picked = mainWindow
      ? await dialog.showOpenDialog(mainWindow, options)
      : await dialog.showOpenDialog(options)
    if (picked.canceled || picked.filePaths.length === 0) return { ok: false, dir: '' }
    return { ok: true, dir: picked.filePaths[0] }
  })

  ipcMain.handle('report:monthlyNow', async () => {
    const written = await runMonthlyReport('now')
    if (written.length === 0) return { ok: false, message: t('main.pdfMonthlyEmpty') }
    return { ok: true, message: t('main.saved', { path: written.join(', ') }) }
  })
}
