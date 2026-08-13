import { analyzeFromReports } from '../shared/analyze'
import type { AnalyzeResult } from '../shared/types'
import { parseLocalBuffers } from './analyze'
import { LOCAL_IMPORT_ACCOUNT_KEY, accountKeyFor, importReports, loadCachedReports } from './cache'

/** Account a file import is attributed to (the active IMAP account, if any). */
export interface ImportTargetAccount {
  user: string
  host: string
  mailbox: string
}

/** Cache slot for imports: the given account, or the shared local slot. */
export function importCacheKey(account: ImportTargetAccount | null): string {
  if (account?.user && account.host) {
    return accountKeyFor(account.user, account.host, account.mailbox)
  }
  return LOCAL_IMPORT_ACCOUNT_KEY
}

/**
 * Parse local report files, persist them into the target cache slot and return
 * the analysis of the merged data set, so a file import behaves like a fetch.
 */
export async function importLocalFiles(
  files: Array<{ name: string; data: Buffer }>,
  account: ImportTargetAccount | null
): Promise<AnalyzeResult> {
  const parsed = await parseLocalBuffers(files)
  const accountKey = importCacheKey(account)

  try {
    const stored = importReports({
      accountKey,
      reports: parsed.reports,
      forensicReports: parsed.forensicReports
    })
    const cached = loadCachedReports(accountKey)
    const result = analyzeFromReports(cached.reports, {
      skipped: parsed.skipped,
      errors: parsed.errors,
      fromCache: true,
      newReports: stored.addedReports,
      newForensicReports: stored.addedForensic,
      forensicReports: cached.forensicReports
    })
    result.imported = {
      added: stored.addedReports,
      updated: stored.updatedReports,
      addedForensic: stored.addedForensic,
      persisted: true
    }
    return result
  } catch (err) {
    // Keep the parsed data usable for this session even if the cache write fails.
    const message = err instanceof Error ? err.message : String(err)
    parsed.errors = [...parsed.errors, `Cache: ${message}`].slice(0, 50)
    parsed.imported = {
      added: 0,
      updated: 0,
      addedForensic: 0,
      persisted: false
    }
    return parsed
  }
}

/** Reports imported from files while no IMAP account existed, or null when empty. */
export function loadLocalImportResult(): AnalyzeResult | null {
  const cached = loadCachedReports(LOCAL_IMPORT_ACCOUNT_KEY)
  if (cached.reports.length === 0 && cached.forensicReports.length === 0) return null
  return analyzeFromReports(cached.reports, {
    fromCache: true,
    newReports: 0,
    forensicReports: cached.forensicReports
  })
}
