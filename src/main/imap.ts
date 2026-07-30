import { ImapFlow } from 'imapflow'
import type {
  AnalyzeProgress,
  AnalyzeResult,
  ImapConnectionInput,
  TestConnectionResult
} from '../shared/types'
import { analyzeFromReports, parseMimeSources } from './analyze'
import { accountKeyFor, loadCachedReports, mergeReports, saveCache } from './cache'

export type ProgressCallback = (progress: AnalyzeProgress) => void

function createClient(settings: ImapConnectionInput): ImapFlow {
  return new ImapFlow({
    host: settings.host,
    port: settings.port,
    secure: settings.secure,
    auth: {
      user: settings.user,
      pass: settings.password
    },
    logger: false,
    connectionTimeout: 30_000,
    greetingTimeout: 30_000
  })
}

export async function testConnection(settings: ImapConnectionInput): Promise<TestConnectionResult> {
  const client = createClient(settings)
  try {
    await client.connect()
    const lock = await client.getMailboxLock(settings.mailbox)
    try {
      const exists =
        client.mailbox && typeof client.mailbox === 'object' ? client.mailbox.exists : 0
      return {
        ok: true,
        message: `Verbindung OK — Ordner „${settings.mailbox}“ enthält ${exists} Nachrichten.`,
        mailboxExists: exists
      }
    } finally {
      lock.release()
    }
  } catch (err) {
    return {
      ok: false,
      message: err instanceof Error ? err.message : String(err)
    }
  } finally {
    try {
      await client.logout()
    } catch {
      client.close()
    }
  }
}

export function loadCachedAnalyzeResult(settings: ImapConnectionInput): AnalyzeResult {
  const key = accountKeyFor(settings.user, settings.host, settings.mailbox)
  const { reports } = loadCachedReports(key)
  return analyzeFromReports(reports, { fromCache: true, newReports: 0 })
}

export async function fetchAndAnalyze(
  settings: ImapConnectionInput,
  onProgress: ProgressCallback
): Promise<AnalyzeResult> {
  const client = createClient(settings)
  const accountKey = accountKeyFor(settings.user, settings.host, settings.mailbox)
  const cached = loadCachedReports(accountKey)
  const lastUid = cached.meta.lastUid

  onProgress({
    phase: 'connecting',
    processed: 0,
    total: 0,
    parsed: 0,
    skipped: 0,
    message: `Verbinde mit ${settings.host}…`
  })

  try {
    await client.connect()
    const lock = await client.getMailboxLock(settings.mailbox)

    try {
      onProgress({
        phase: 'searching',
        processed: 0,
        total: 0,
        parsed: 0,
        skipped: 0,
        message:
          lastUid > 0 ? `Suche neue DMARC-Reports (nach UID ${lastUid})…` : 'Suche DMARC-Reports…'
      })

      const filter = settings.subjectFilter.trim()
      const searchQuery: Record<string, unknown> = filter
        ? { subject: filter }
        : { all: true as const }
      if (lastUid > 0) {
        searchQuery.uid = `${lastUid + 1}:*`
      }

      const uids = await client.search(searchQuery, { uid: true })
      const uidList = Array.isArray(uids) ? uids.filter((u) => u > lastUid) : []

      if (uidList.length === 0) {
        onProgress({
          phase: 'done',
          processed: 0,
          total: 0,
          parsed: cached.reports.length,
          skipped: 0,
          message:
            cached.reports.length > 0
              ? `Keine neuen Nachrichten — ${cached.reports.length} Reports aus Cache.`
              : 'Keine passenden Nachrichten gefunden.'
        })
        return analyzeFromReports(cached.reports, {
          fromCache: true,
          newReports: 0
        })
      }

      const total = uidList.length
      onProgress({
        phase: 'fetching',
        processed: 0,
        total,
        parsed: 0,
        skipped: 0,
        message: `${total} neue Nachrichten werden geladen…`
      })

      const sources: Array<{ uid: number; source: Buffer }> = []
      let processed = 0
      let maxUid = lastUid

      for await (const message of client.fetch(
        uidList,
        { uid: true, source: true },
        { uid: true }
      )) {
        processed += 1
        if (message.uid > maxUid) maxUid = message.uid
        if (message.source) {
          sources.push({
            uid: message.uid,
            source: Buffer.from(message.source)
          })
        }
        if (processed % 5 === 0 || processed === total) {
          onProgress({
            phase: 'fetching',
            processed,
            total,
            parsed: 0,
            skipped: 0,
            message: `Geladen: ${processed}/${total}`
          })
        }
      }

      onProgress({
        phase: 'parsing',
        processed: total,
        total,
        parsed: 0,
        skipped: 0,
        message: `${sources.length} Nachrichten werden geparst…`
      })

      const fresh = await parseMimeSources(sources)
      const merged = mergeReports(cached.reports, fresh.reports)

      // Detect source IPs never seen for this account before. When the cache
      // predates this feature (reports but no known IPs), seed silently.
      const known = new Set(cached.meta.knownSourceIps)
      const seedOnly = known.size === 0
      if (seedOnly) {
        for (const r of cached.reports) for (const rec of r.records) known.add(rec.sourceIp)
      }
      const freshIps = new Set<string>()
      for (const r of fresh.reports) for (const rec of r.records) freshIps.add(rec.sourceIp)
      const newSourceIps =
        cached.reports.length === 0 || seedOnly
          ? []
          : [...freshIps].filter((ip) => !known.has(ip)).sort()
      for (const ip of freshIps) known.add(ip)

      const result = analyzeFromReports(merged, {
        skipped: fresh.skipped,
        errors: fresh.errors,
        fromCache: cached.reports.length > 0,
        newReports: fresh.reports.length
      })
      result.newSourceIps = newSourceIps

      saveCache({
        accountKey,
        reports: merged,
        lastUid: maxUid,
        lastFailingTotal: result.aggregate.failing,
        knownSourceIps: [...known].sort()
      })

      if (settings.markSeenAfterFetch && uidList.length > 0) {
        try {
          await client.messageFlagsAdd(uidList, ['\\Seen'], { uid: true })
        } catch {
          // Markieren ist optional — Abruf gilt trotzdem als erfolgreich.
        }
      }

      onProgress({
        phase: 'done',
        processed: total,
        total,
        parsed: result.reports.length,
        skipped: result.skipped,
        message: `${fresh.reports.length} neu, ${result.reports.length} Reports gesamt, ${result.skipped} übersprungen.`
      })

      return result
    } finally {
      lock.release()
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    onProgress({
      phase: 'error',
      processed: 0,
      total: 0,
      parsed: 0,
      skipped: 0,
      message
    })
    throw err
  } finally {
    try {
      await client.logout()
    } catch {
      client.close()
    }
  }
}

export function previousFailingTotal(settings: ImapConnectionInput): number {
  const key = accountKeyFor(settings.user, settings.host, settings.mailbox)
  return loadCachedReports(key).meta.lastFailingTotal
}
