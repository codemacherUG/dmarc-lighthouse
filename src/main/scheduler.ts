import type { BrowserWindow } from 'electron'
import { ALL_ACCOUNTS_ID, isAllAccountsId } from '../shared/account'
import { analyzeFromReports } from '../shared/analyze'
import { isDkimSelectorChecked } from '../shared/dkim-selector'
import { t } from '../shared/i18n'
import {
  isMonthlyReportDue,
  monthlyReportFilename,
  periodForReports,
  previousMonthRange
} from '../shared/report-period'
import { alertableSendingSources } from '../shared/sending-services'
import type {
  AccountPublic,
  AnalyzeResult,
  NewSendingSourceGroup,
  ReportRow
} from '../shared/types'
import {
  LOCAL_IMPORT_ACCOUNT_KEY,
  accountKeyFor,
  getCachedReportDomains,
  getDnsHealthCache,
  getDomainDkimSelectors,
  getLatestDnsHistoryCheckAt,
  loadCachedReports,
  pruneExpiredReports,
  recordDnsHistory,
  recordTransportHistory,
  upsertDnsHealthCache
} from './cache'
import { checkDomainDns } from './dnscheck'
import { fetchAndAnalyze, loadCombinedCachedAnalyzeResult, previousFailingTotal } from './imap'
import type { ImportTargetAccount } from './import'
import {
  buildPdfReport,
  defaultReportDir,
  domainHealthFromReports,
  forensicInPeriod,
  groupReportsByDomain,
  reportsInPeriod,
  writeReportFile
} from './pdf-report'
import {
  isIgnoredSource,
  loadSettings,
  parseIgnoredSources,
  resolveAccountConnection,
  setMonthlyReportRun
} from './settings'
import { checkTransportSecurity } from './transport'

export interface SchedulerHooks {
  getMainWindow: () => BrowserWindow | null
  notify: (body: string) => void
  markTrayAttentionIfHidden: () => void
}

let hooks: SchedulerHooks = {
  getMainWindow: () => null,
  notify: () => undefined,
  markTrayAttentionIfHidden: () => undefined
}

export function configureScheduler(nextHooks: SchedulerHooks): void {
  hooks = nextHooks
}

let autoFetchTimer: ReturnType<typeof setInterval> | null = null
let monthlyReportTimer: ReturnType<typeof setInterval> | null = null
let dnsAutoCheckTimer: ReturnType<typeof setInterval> | null = null
let monthlyReportInFlight = false
let fetchInFlight = false
let dnsAutoCheckInFlight = false
const DNS_AUTO_CHECK_INTERVAL_MS = 24 * 60 * 60_000

export function accountReady(account: AccountPublic): boolean {
  return Boolean(account.user && (account.hasPassword || account.hasOAuth))
}

/** Cache owner for file imports: the requested account, the active account, or the local slot. */
export function importTargetAccount(accountId?: string | null): ImportTargetAccount | null {
  try {
    const settingsPub = loadSettings()
    const targetId = accountId ?? settingsPub.activeAccountId
    if (!targetId || isAllAccountsId(targetId) || targetId === LOCAL_IMPORT_ACCOUNT_KEY) {
      return null
    }
    const account = settingsPub.accounts.find((a) => a.id === targetId)
    if (!account?.user || !account.host) return null
    return { user: account.user, host: account.host, mailbox: account.mailbox }
  } catch {
    return null
  }
}

/** All cache keys included in the combined "All accounts" view. */
export function allAccountsCacheKeys(settingsPub = loadSettings()): string[] {
  const keys = settingsPub.accounts
    .filter((a) => a.user && a.host)
    .map((a) => accountKeyFor(a.user, a.host, a.mailbox))
  keys.push(LOCAL_IMPORT_ACCOUNT_KEY)
  return [...new Set(keys)]
}

function isDnsHistoryCheckDue(checkedAt: string | null, now: number): boolean {
  if (!checkedAt) return true
  const timestamp = new Date(checkedAt).getTime()
  return !Number.isFinite(timestamp) || now - timestamp >= DNS_AUTO_CHECK_INTERVAL_MS
}

/** Pass rate over reports whose window ends within the last `days` days, or null without data. */
function passRateLastDays(reports: ReportRow[], days: number): number | null {
  const cutoff = Date.now() - days * 86_400_000
  let total = 0
  let passing = 0
  for (const r of reports) {
    const end = new Date(r.dateEnd || r.dateBegin).getTime()
    if (Number.isNaN(end) || end < cutoff) continue
    total += r.total
    passing += r.passing
  }
  if (total === 0) return null
  return Math.round((passing / total) * 1000) / 10
}

/** Names a new source-IP group by detected network and From domain. */
function describeSendingSourceGroup(group: NewSendingSourceGroup): string {
  const provider = group.provider
    ? group.provider.replace(/\s+/g, '-')
    : t('main.alertUnknownProvider')
  return group.domain
    ? t('main.alertSendingSourceItem', { provider, domain: group.domain })
    : t('main.alertSendingSourceItemNoDomain', { provider })
}

function runAlerts(account: AccountPublic, prevFailing: number, result: AnalyzeResult): void {
  const global = loadSettings().global
  const suffix = loadSettings().accounts.length > 1 ? ` (${account.label})` : ''

  if (global.notifyOnFail && result.aggregate.failing > prevFailing) {
    const delta = result.aggregate.failing - prevFailing
    hooks.notify(
      t('main.alertFail', {
        delta,
        total: result.aggregate.failing,
        suffix
      })
    )
  }

  if (global.passRateAlertThreshold > 0 && (result.newReports ?? 0) > 0) {
    const rate = passRateLastDays(result.reports, 7)
    if (rate != null && rate < global.passRateAlertThreshold) {
      hooks.notify(
        t('main.alertPassRate', {
          rate: rate.toFixed(1),
          threshold: global.passRateAlertThreshold,
          suffix
        })
      )
    }
  }

  if (global.notifyNewSource && result.newSourceIps && result.newSourceIps.length > 0) {
    const matchers = parseIgnoredSources(global.ignoredSources)
    const freshIps = new Set(result.newSourceIps)
    const groups = alertableSendingSources(result.newSendingSources ?? [])
      .map((g) => ({
        ...g,
        ips: g.ips.filter((ip) => freshIps.has(ip) && !isIgnoredSource(ip, matchers))
      }))
      .filter((g) => g.ips.length > 0)

    if (groups.length > 0) {
      const shown = groups.slice(0, 3).map(describeSendingSourceGroup).join(', ')
      const more = groups.length > 3 ? t('main.alertMore', { count: groups.length - 3 }) : ''
      hooks.notify(t('main.alertNewSendingSource', { shown, more, suffix }))
    } else if (!result.newSendingSources) {
      // Fallback for the rare case sending-service enrichment failed for this fetch.
      const relevant = result.newSourceIps.filter((ip) => !isIgnoredSource(ip, matchers))
      if (relevant.length > 0) {
        const shown = relevant.slice(0, 3).join(', ')
        const more = relevant.length > 3 ? t('main.alertMore', { count: relevant.length - 3 }) : ''
        hooks.notify(t('main.alertNewSource', { shown, more, suffix }))
      }
    }
  }
}

export async function runSavedFetch(accountId?: string | null): Promise<AnalyzeResult> {
  if (fetchInFlight) {
    throw new Error(t('main.fetchInFlight'))
  }
  fetchInFlight = true
  try {
    const targetId = accountId ?? loadSettings().activeAccountId
    if (isAllAccountsId(targetId)) {
      return await fetchAllAccountsCombined()
    }
    return await fetchAccount(targetId)
  } finally {
    fetchInFlight = false
  }
}

async function fetchAccount(accountId?: string | null): Promise<AnalyzeResult> {
  const settingsPub = loadSettings()
  const id = accountId ?? settingsPub.activeAccountId
  const account = settingsPub.accounts.find((a) => a.id === id)
  if (!account) throw new Error(t('main.noAccount'))

  const connection = await resolveAccountConnection(account.id)
  const prevFailing = previousFailingTotal(connection)
  const result = await fetchAndAnalyze(connection, (progress) => {
    hooks.getMainWindow()?.webContents.send('imap:progress', progress)
  })
  const retentionDays = settingsPub.global.reportRetentionDays
  if (retentionDays > 0) {
    pruneExpiredReports(retentionDays)
  }
  result.accountId = account.id
  runAlerts(account, prevFailing, result)
  if ((result.newReports ?? 0) > 0) {
    hooks.markTrayAttentionIfHidden()
  }
  hooks.getMainWindow()?.webContents.send('imap:result', result)
  return result
}

/** Fetch all ready accounts and return the combined AnalyzeResult across all accounts. */
async function fetchAllAccountsCombined(): Promise<AnalyzeResult> {
  const settingsPub = loadSettings()
  const readyAccounts = settingsPub.accounts.filter((a) => accountReady(a))
  if (readyAccounts.length === 0) throw new Error(t('main.noAccount'))

  let newReports = 0
  let newForensicReports = 0
  let newTlsRptReports = 0
  let skipped = 0
  const errors: string[] = []

  for (const account of readyAccounts) {
    try {
      const res = await fetchAccount(account.id)
      newReports += res.newReports ?? 0
      newForensicReports += res.newForensicReports ?? 0
      newTlsRptReports += res.newTlsRptReports ?? 0
      skipped += res.skipped ?? 0
      for (const err of res.errors ?? []) {
        errors.push(`${account.label}: ${err}`)
      }
    } catch (err) {
      const msg = `${account.label}: ${err instanceof Error ? err.message : String(err)}`
      errors.push(msg)
      hooks.getMainWindow()?.webContents.send('imap:progress', {
        phase: 'error',
        processed: 0,
        total: 0,
        parsed: 0,
        skipped: 0,
        message: msg
      })
    }
  }

  const combined = await loadCombinedCachedAnalyzeResult(allAccountsCacheKeys(settingsPub), {
    newReports,
    newForensicReports,
    newTlsRptReports,
    skipped,
    errors: errors.slice(0, 50)
  })
  combined.accountId = ALL_ACCOUNTS_ID
  hooks.getMainWindow()?.webContents.send('imap:result', combined)
  return combined
}

/** Fetch all configured accounts sequentially (auto-fetch / tray action). */
export async function runAutoFetchAll(): Promise<void> {
  if (fetchInFlight) return
  fetchInFlight = true
  try {
    const settingsPub = loadSettings()
    if (isAllAccountsId(settingsPub.activeAccountId)) {
      await fetchAllAccountsCombined()
      return
    }
    for (const account of settingsPub.accounts) {
      if (!accountReady(account)) continue
      try {
        await fetchAccount(account.id)
      } catch (err) {
        hooks.getMainWindow()?.webContents.send('imap:progress', {
          phase: 'error',
          processed: 0,
          total: 0,
          parsed: 0,
          skipped: 0,
          message: `${account.label}: ${err instanceof Error ? err.message : String(err)}`
        })
      }
    }
  } finally {
    fetchInFlight = false
  }
}

export function stopAutoFetch(): void {
  if (autoFetchTimer) {
    clearInterval(autoFetchTimer)
    autoFetchTimer = null
  }
}

export function scheduleAutoFetch(): void {
  stopAutoFetch()
  const settingsPub = loadSettings()
  const minutes = settingsPub.global.autoFetchMinutes
  const hasAccount = settingsPub.accounts.some((a) => accountReady(a))
  if (!minutes || minutes <= 0 || !hasAccount) return

  autoFetchTimer = setInterval(() => {
    void runAutoFetchAll()
  }, minutes * 60_000)
}

async function runDnsAutoCheck(): Promise<void> {
  if (dnsAutoCheckInFlight) return
  dnsAutoCheckInFlight = true
  const failures: string[] = []
  try {
    const now = Date.now()
    for (const domain of getCachedReportDomains()) {
      const dnsCheckedAt = getLatestDnsHistoryCheckAt(domain, 'dns')
      const transportCheckedAt = getLatestDnsHistoryCheckAt(domain, 'transport')
      const dnsIsDue = isDnsHistoryCheckDue(dnsCheckedAt, now)
      const transportIsDue = isDnsHistoryCheckDue(transportCheckedAt, now)
      if (!dnsIsDue && !transportIsDue) continue

      if (dnsIsDue) {
        try {
          const selectors = getDomainDkimSelectors(domain)
            .filter(isDkimSelectorChecked)
            .map((selector) => selector.selector)
          const dnsResult = await checkDomainDns(domain, selectors)
          recordDnsHistory(dnsResult)
          upsertDnsHealthCache(dnsResult.domain, dnsResult, undefined, { replaceDkim: true })
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error)
          failures.push(`${domain}: ${message}`)
          console.error(`Automatic DNS check failed for ${domain}`, error)
        }
      }

      if (transportIsDue) {
        try {
          recordTransportHistory(await checkTransportSecurity(domain))
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error)
          failures.push(`${domain} (Transport): ${message}`)
          console.error(`Automatic transport check failed for ${domain}`, error)
        }
      }
    }
    if (failures.length > 0) {
      hooks.notify(
        t('main.dnsAutoCheckFailed', {
          count: failures.length,
          message: failures[0]
        })
      )
    }
  } finally {
    dnsAutoCheckInFlight = false
  }
}

export function stopDnsAutoCheck(): void {
  if (dnsAutoCheckTimer) {
    clearInterval(dnsAutoCheckTimer)
    dnsAutoCheckTimer = null
  }
}

export function scheduleDnsAutoCheck(): void {
  stopDnsAutoCheck()
  const tick = (): void => {
    void runDnsAutoCheck().catch((error) => {
      console.error('Automatic DNS check run failed', error)
      hooks.notify(
        t('main.dnsAutoCheckFailed', {
          count: 1,
          message: error instanceof Error ? error.message : String(error)
        })
      )
    })
  }
  dnsAutoCheckTimer = setInterval(tick, 60 * 60_000)
  setTimeout(tick, 30_000)
}

/** Cache slots a monthly report can be built from: IMAP accounts plus local imports. */
function reportSources(): Array<{ key: string; label: string | null }> {
  const settingsPub = loadSettings()
  const sources: Array<{ key: string; label: string | null }> = settingsPub.accounts
    .filter((a) => a.user && a.host)
    .map((a) => ({ key: accountKeyFor(a.user, a.host, a.mailbox), label: a.label }))
  if (sources.length === 0) {
    sources.push({ key: LOCAL_IMPORT_ACCOUNT_KEY, label: null })
  }
  return sources
}

/**
 * Write one PDF per domain. An IMAP account is only the mailbox.
 * `scheduled` covers the finished calendar month; `now` also includes domains
 * that only have data in a later month (their latest month).
 */
export async function runMonthlyReport(mode: 'scheduled' | 'now' = 'scheduled'): Promise<string[]> {
  if (monthlyReportInFlight) return []
  monthlyReportInFlight = true
  try {
    return await writeMonthlyReports(mode)
  } finally {
    monthlyReportInFlight = false
  }
}

async function writeMonthlyReports(mode: 'scheduled' | 'now'): Promise<string[]> {
  const global = loadSettings().global
  const dir = global.pdfMonthlyDir.trim() || defaultReportDir()
  const scheduledPeriod = previousMonthRange()

  const sources = reportSources().map((source) => {
    const cached = loadCachedReports(source.key)
    return {
      label: source.label,
      reports: cached.reports,
      forensicReports: cached.forensicReports
    }
  })

  const written: string[] = []
  for (const slice of groupReportsByDomain(sources)) {
    const stamps = [
      ...slice.reports.flatMap((r) => [r.dateBegin, r.dateEnd]),
      ...slice.forensicReports.map((f) => f.arrivalDate ?? '')
    ].filter(Boolean)
    const period = mode === 'scheduled' ? scheduledPeriod : periodForReports(stamps)
    if (!period) continue
    const reports = reportsInPeriod(slice.reports, period)
    const forensicReports = forensicInPeriod(slice.forensicReports, period)
    if (reports.length === 0 && forensicReports.length === 0) continue

    const result = analyzeFromReports(reports, { fromCache: true, forensicReports })
    const pdf = await buildPdfReport(result, {
      month: period.month,
      domain: slice.domain,
      account: slice.accountLabels.length === 1 ? slice.accountLabels[0] : null,
      domains: domainHealthFromReports(reports, (domain) => getDnsHealthCache(domain)),
      host: hooks.getMainWindow()
    })
    written.push(writeReportFile(dir, monthlyReportFilename(slice.domain, period.month), pdf))
  }

  setMonthlyReportRun(new Date().toISOString())
  if (written.length > 0) {
    hooks.notify(t('main.pdfMonthlyDone', { count: written.length, dir }))
  }
  return written
}

export function stopMonthlyReport(): void {
  if (monthlyReportTimer) {
    clearInterval(monthlyReportTimer)
    monthlyReportTimer = null
  }
}

/**
 * Check hourly whether the finished month still needs its report. An interval is
 * enough because the run is idempotent per month and survives a sleeping laptop.
 */
export function scheduleMonthlyReport(): void {
  stopMonthlyReport()
  if (!loadSettings().global.pdfMonthlyEnabled) return
  const tick = (): void => {
    const global = loadSettings().global
    if (!global.pdfMonthlyEnabled) return
    if (!isMonthlyReportDue(global.pdfMonthlyLastRun || null)) return
    void runMonthlyReport().catch((err) => {
      hooks.notify(
        t('main.pdfMonthlyFailed', { message: err instanceof Error ? err.message : String(err) })
      )
    })
  }
  monthlyReportTimer = setInterval(tick, 60 * 60_000)
  setTimeout(tick, 30_000)
}
