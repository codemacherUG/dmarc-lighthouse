import { ImapFlow } from 'imapflow'
import type {
  AnalyzeProgress,
  AnalyzeResult,
  CreateMailboxResult,
  ImapConnectionInput,
  ListMailboxesResult,
  MailboxListEntry,
  TestConnectionResult
} from '../shared/types'
import { analyzeFromReports, parseMimeSources } from './analyze'
import {
  accountKeyFor,
  loadCachedReports,
  mergeForensicReports,
  mergeReports,
  saveCache
} from './cache'
import { t } from '../shared/i18n'

export type ProgressCallback = (progress: AnalyzeProgress) => void

interface MimeSource {
  uid: number
  source: Buffer
}

interface MailboxFetchResult {
  sources: MimeSource[]
  uidList: number[]
  maxUid: number
}

function createClient(settings: ImapConnectionInput): ImapFlow {
  const auth =
    settings.authMode === 'oauth' && settings.accessToken
      ? { user: settings.user, accessToken: settings.accessToken }
      : { user: settings.user, pass: settings.password ?? '' }

  return new ImapFlow({
    host: settings.host,
    port: settings.port,
    secure: settings.secure,
    auth,
    logger: false,
    connectionTimeout: 30_000,
    greetingTimeout: 30_000
  })
}

function normalizeMailbox(path: string): string {
  return path.trim()
}

function formatImapError(err: unknown): string {
  if (!(err instanceof Error)) return String(err)
  const e = err as Error & {
    responseText?: string
    responseStatus?: string
    serverResponseCode?: string
    response?: unknown
  }
  const detail =
    (typeof e.responseText === 'string' && e.responseText) ||
    (typeof e.response === 'string' && e.response) ||
    ''
  const code = e.serverResponseCode || e.responseStatus || ''
  if (detail && code) return `${code}: ${detail}`
  if (detail) return detail
  if (code && e.message === 'Command failed') return `${code}: ${e.message}`
  return e.message
}

/** Split a user-entered folder path into hierarchy segments for imapflow. */
function mailboxSegments(path: string): string[] {
  return path
    .split(/[/.]/)
    .map((p) => p.trim())
    .filter(Boolean)
    .filter((p, i) => !(i === 0 && p.toUpperCase() === 'INBOX'))
}

/** Destination folder for moves; empty / same as source → disabled. */
function resolvedArchiveMailbox(settings: ImapConnectionInput): string {
  const archive = normalizeMailbox(settings.archiveMailbox ?? '')
  const source = normalizeMailbox(settings.mailbox) || 'INBOX'
  if (!archive || archive.toLowerCase() === source.toLowerCase()) return ''
  return archive
}

function segmentKey(path: string): string {
  return path
    .split(/[/.]/)
    .map((p) => p.trim())
    .filter(Boolean)
    .map((p) => p.toLowerCase())
    .join('/')
}

/**
 * Map a user/settings path to the exact server LIST path (delimiter + namespace).
 * Falls back to the requested path if nothing matches.
 */
async function resolveServerMailboxPath(client: ImapFlow, wanted: string): Promise<string> {
  const target = normalizeMailbox(wanted)
  if (!target) return target
  const listed = await client.list()
  const wantedKey = segmentKey(target)
  const wantedWithoutInbox = wantedKey.replace(/^inbox\//, '')

  for (const entry of listed) {
    const flags = entry.flags ?? new Set<string>()
    if (flags.has('\\Noselect') || flags.has('\\NonExistent')) continue
    const key = segmentKey(entry.path)
    if (key === wantedKey) return entry.path
    if (key.replace(/^inbox\//, '') === wantedWithoutInbox) return entry.path
  }
  return target
}

async function withClient<T>(
  settings: ImapConnectionInput,
  fn: (client: ImapFlow) => Promise<T>
): Promise<T> {
  const client = createClient(settings)
  try {
    await client.connect()
    return await fn(client)
  } finally {
    try {
      await client.logout()
    } catch {
      client.close()
    }
  }
}

export async function testConnection(settings: ImapConnectionInput): Promise<TestConnectionResult> {
  try {
    return await withClient(settings, async (client) => {
      const lock = await client.getMailboxLock(settings.mailbox)
      try {
        const exists =
          client.mailbox && typeof client.mailbox === 'object' ? client.mailbox.exists : 0
        return {
          ok: true,
          message: t('imap.connectOk', { mailbox: settings.mailbox, count: exists }),
          mailboxExists: exists
        }
      } finally {
        lock.release()
      }
    })
  } catch (err) {
    return {
      ok: false,
      message: err instanceof Error ? err.message : String(err)
    }
  }
}

export async function listMailboxes(settings: ImapConnectionInput): Promise<ListMailboxesResult> {
  try {
    return await withClient(settings, async (client) => {
      const listed = await client.list()
      const mailboxes: MailboxListEntry[] = []
      for (const entry of listed) {
        const flags = entry.flags ?? new Set<string>()
        if (flags.has('\\Noselect') || flags.has('\\NonExistent')) continue
        mailboxes.push({
          path: entry.path,
          name: entry.name,
          specialUse: entry.specialUse
        })
      }
      mailboxes.sort((a, b) => a.path.localeCompare(b.path, undefined, { sensitivity: 'base' }))
      return {
        ok: true,
        message: t('imap.listOk', { count: mailboxes.length }),
        mailboxes
      }
    })
  } catch (err) {
    return {
      ok: false,
      message: err instanceof Error ? err.message : String(err),
      mailboxes: []
    }
  }
}

export async function createMailbox(
  settings: ImapConnectionInput,
  path: string
): Promise<CreateMailboxResult> {
  const mailbox = normalizeMailbox(path)
  if (!mailbox) {
    return { ok: false, message: t('imap.createMailboxEmpty'), path: '', created: false }
  }
  const segments = mailboxSegments(mailbox)
  if (segments.length === 0) {
    return { ok: false, message: t('imap.createMailboxEmpty'), path: '', created: false }
  }
  try {
    return await withClient(settings, async (client) => {
      // Array form: imapflow joins with the server delimiter and applies the namespace prefix.
      const result = await client.mailboxCreate(segments)
      if (!result?.path) {
        return {
          ok: false,
          message: t('imap.createMailboxFailed', { detail: 'Command failed' }),
          path: mailbox,
          created: false
        }
      }
      return {
        ok: true,
        message: result.created
          ? t('imap.createMailboxOk', { mailbox: result.path })
          : t('imap.createMailboxExists', { mailbox: result.path }),
        path: result.path,
        created: Boolean(result.created)
      }
    })
  } catch (err) {
    return {
      ok: false,
      message: t('imap.createMailboxFailed', { detail: formatImapError(err) }),
      path: mailbox,
      created: false
    }
  }
}

export function loadCachedAnalyzeResult(settings: ImapConnectionInput): AnalyzeResult {
  const key = accountKeyFor(settings.user, settings.host, settings.mailbox)
  const { reports, forensicReports } = loadCachedReports(key)
  return analyzeFromReports(reports, {
    fromCache: true,
    newReports: 0,
    forensicReports
  })
}

async function fetchFromMailbox(
  client: ImapFlow,
  mailbox: string,
  lastUid: number,
  subjectFilter: string,
  onProgress: ProgressCallback,
  label?: string
): Promise<MailboxFetchResult> {
  const path = await resolveServerMailboxPath(client, mailbox)
  const lock = await client.getMailboxLock(path)
  try {
    const folderLabel = label || path
    onProgress({
      phase: 'searching',
      processed: 0,
      total: 0,
      parsed: 0,
      skipped: 0,
      message: label
        ? lastUid > 0
          ? t('imap.searchingNewFolder', { mailbox: folderLabel, uid: lastUid })
          : t('imap.searchingFolder', { mailbox: folderLabel })
        : lastUid > 0
          ? t('imap.searchingNew', { uid: lastUid })
          : t('imap.searching')
    })

    const filter = subjectFilter.trim()
    const searchQuery: Record<string, unknown> = filter
      ? { subject: filter }
      : { all: true as const }
    if (lastUid > 0) {
      searchQuery.uid = `${lastUid + 1}:*`
    }

    const uids = await client.search(searchQuery, { uid: true })
    const uidList = Array.isArray(uids) ? uids.filter((u) => u > lastUid) : []

    if (uidList.length === 0) {
      return { sources: [], uidList: [], maxUid: lastUid }
    }

    const total = uidList.length
    onProgress({
      phase: 'fetching',
      processed: 0,
      total,
      parsed: 0,
      skipped: 0,
      message: label
        ? t('imap.fetchingFolder', { mailbox: folderLabel, count: total })
        : t('imap.fetching', { count: total })
    })

    const sources: MimeSource[] = []
    let processed = 0
    let maxUid = lastUid

    for await (const message of client.fetch(uidList, { uid: true, source: true }, { uid: true })) {
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
          message: t('imap.loaded', { processed, total })
        })
      }
    }

    return { sources, uidList, maxUid }
  } finally {
    lock.release()
  }
}

/** All UIDs matching the subject filter (seen + unseen). Empty filter → []. */
async function searchMatchingUids(
  client: ImapFlow,
  mailbox: string,
  subjectFilter: string
): Promise<number[]> {
  const filter = subjectFilter.trim()
  if (!filter) return []
  const path = await resolveServerMailboxPath(client, mailbox)
  const lock = await client.getMailboxLock(path)
  try {
    const uids = await client.search({ subject: filter }, { uid: true })
    return Array.isArray(uids) ? uids.filter((u) => u > 0).sort((a, b) => a - b) : []
  } finally {
    lock.release()
  }
}

function chunkUids(uids: number[], size = 100): number[][] {
  const out: number[][] = []
  for (let i = 0; i < uids.length; i += size) out.push(uids.slice(i, i + size))
  return out
}

async function markSeen(
  client: ImapFlow,
  mailbox: string,
  uidList: number[]
): Promise<void> {
  if (uidList.length === 0) return
  const path = await resolveServerMailboxPath(client, mailbox)
  const lock = await client.getMailboxLock(path)
  try {
    for (const chunk of chunkUids(uidList)) {
      // imapflow returns false on failure instead of throwing.
      const ok = await client.messageFlagsAdd(chunk, ['\\Seen'], { uid: true })
      if (!ok) {
        throw new Error(`STORE \\Seen rejected (${path})`)
      }
    }
  } finally {
    lock.release()
  }
}

async function moveMessages(
  client: ImapFlow,
  mailbox: string,
  uidList: number[],
  destination: string,
  onProgress: ProgressCallback
): Promise<void> {
  if (uidList.length === 0) return
  const sourcePath = await resolveServerMailboxPath(client, mailbox)
  const destPath = await resolveServerMailboxPath(client, destination)
  if (segmentKey(sourcePath) === segmentKey(destPath)) {
    throw new Error(t('imap.moveSameFolder'))
  }
  onProgress({
    phase: 'moving',
    processed: 0,
    total: uidList.length,
    parsed: 0,
    skipped: 0,
    message: t('imap.moving', { count: uidList.length, mailbox: destPath })
  })
  const lock = await client.getMailboxLock(sourcePath)
  try {
    for (const chunk of chunkUids(uidList)) {
      // imapflow returns false on MOVE failure instead of throwing.
      let result: unknown = await client.messageMove(chunk, destPath, { uid: true })
      if (!result) {
        // Fallback: COPY + delete (servers without MOVE or flaky MOVE).
        const copied = await client.messageCopy(chunk, destPath, { uid: true })
        if (!copied) {
          throw new Error(t('imap.moveRejected', { mailbox: destPath }))
        }
        const deleted = await client.messageDelete(chunk, { uid: true })
        if (!deleted) {
          throw new Error(t('imap.moveRejected', { mailbox: destPath }))
        }
        result = copied
      }
    }
  } finally {
    lock.release()
  }
}

/** Move (and optionally mark seen) every matching message still in the fetch folder. */
async function sweepSourceToArchive(
  client: ImapFlow,
  settings: ImapConnectionInput,
  archiveMailbox: string,
  onProgress: ProgressCallback
): Promise<string[]> {
  const notes: string[] = []
  const moveUids = await searchMatchingUids(client, settings.mailbox, settings.subjectFilter)
  if (moveUids.length === 0) return notes

  if (settings.markSeenAfterFetch) {
    try {
      await markSeen(client, settings.mailbox, moveUids)
      notes.push(t('imap.markSeenOk', { count: moveUids.length }))
    } catch (err) {
      notes.push(t('imap.markSeenFailed', { detail: formatImapError(err) }))
    }
  }

  try {
    const destPath = await resolveServerMailboxPath(client, archiveMailbox)
    await moveMessages(client, settings.mailbox, moveUids, destPath, onProgress)
    notes.push(t('imap.movedNote', { count: moveUids.length, mailbox: destPath }))
  } catch (err) {
    notes.push(t('imap.moveFailed', { detail: formatImapError(err) }))
  }
  return notes
}

export async function fetchAndAnalyze(
  settings: ImapConnectionInput,
  onProgress: ProgressCallback
): Promise<AnalyzeResult> {
  const accountKey = accountKeyFor(settings.user, settings.host, settings.mailbox)
  const cached = loadCachedReports(accountKey)
  const lastUid = cached.meta.lastUid
  const lastUidArchive = cached.meta.lastUidArchive
  const archiveMailbox = resolvedArchiveMailbox(settings)

  onProgress({
    phase: 'connecting',
    processed: 0,
    total: 0,
    parsed: 0,
    skipped: 0,
    message: t('imap.connecting', { host: settings.host })
  })

  try {
    return await withClient(settings, async (client) => {
      const sourceFetch = await fetchFromMailbox(
        client,
        settings.mailbox,
        lastUid,
        settings.subjectFilter,
        onProgress
      )

      let archiveFetch: MailboxFetchResult = {
        sources: [],
        uidList: [],
        maxUid: lastUidArchive
      }
      if (archiveMailbox) {
        archiveFetch = await fetchFromMailbox(
          client,
          archiveMailbox,
          lastUidArchive,
          settings.subjectFilter,
          onProgress,
          archiveMailbox
        )
      }

      const sources = [...sourceFetch.sources, ...archiveFetch.sources]
      const totalFetched = sourceFetch.uidList.length + archiveFetch.uidList.length

      if (totalFetched === 0) {
        const notes: string[] = []
        if (archiveMailbox) {
          notes.push(
            ...(await sweepSourceToArchive(client, settings, archiveMailbox, onProgress))
          )
        }
        const base =
          cached.reports.length > 0 || cached.forensicReports.length > 0
            ? t('imap.noNewCached', { count: cached.reports.length })
            : t('imap.noneFound')
        onProgress({
          phase: 'done',
          processed: 0,
          total: 0,
          parsed: cached.reports.length,
          skipped: 0,
          message: notes.length ? `${base} ${notes.join(' ')}` : base
        })
        return analyzeFromReports(cached.reports, {
          fromCache: true,
          newReports: 0,
          forensicReports: cached.forensicReports
        })
      }

      onProgress({
        phase: 'parsing',
        processed: totalFetched,
        total: totalFetched,
        parsed: 0,
        skipped: 0,
        message: t('imap.parsing', { count: sources.length })
      })

      const fresh = await parseMimeSources(sources)
      const merged = mergeReports(cached.reports, fresh.reports)
      const mergedForensic = mergeForensicReports(
        cached.forensicReports,
        fresh.forensicReports ?? []
      )

      // Detect source IPs never seen for this account before. When the cache
      // predates this feature (reports but no known IPs), seed silently.
      const known = new Set(cached.meta.knownSourceIps)
      const seedOnly = known.size === 0
      if (seedOnly) {
        for (const r of cached.reports) for (const rec of r.records) known.add(rec.sourceIp)
      }
      const freshIps = new Set<string>()
      for (const r of fresh.reports) for (const rec of r.records) freshIps.add(rec.sourceIp)
      for (const f of fresh.forensicReports ?? []) {
        if (f.sourceIp) freshIps.add(f.sourceIp)
      }
      const newSourceIps =
        cached.reports.length === 0 || seedOnly
          ? []
          : [...freshIps].filter((ip) => !known.has(ip)).sort()
      for (const ip of freshIps) known.add(ip)

      const result = analyzeFromReports(merged, {
        skipped: fresh.skipped,
        errors: fresh.errors,
        fromCache: cached.reports.length > 0 || cached.forensicReports.length > 0,
        newReports: fresh.reports.length,
        newForensicReports: fresh.forensicReports?.length ?? 0,
        forensicReports: mergedForensic
      })
      result.newSourceIps = newSourceIps

      saveCache({
        accountKey,
        reports: merged,
        forensicReports: mergedForensic,
        lastUid: sourceFetch.maxUid,
        lastUidArchive: archiveMailbox ? archiveFetch.maxUid : lastUidArchive,
        lastFailingTotal: result.aggregate.failing,
        knownSourceIps: [...known].sort()
      })

      const notes: string[] = []

      // Mark \\Seen on archive UIDs first; source mails are handled by the sweep
      // (mark + move) so leftover inbox matches are cleaned up too.
      if (settings.markSeenAfterFetch && archiveMailbox && archiveFetch.uidList.length > 0) {
        try {
          await markSeen(client, archiveMailbox, archiveFetch.uidList)
        } catch (err) {
          notes.push(t('imap.markSeenFailed', { detail: formatImapError(err) }))
        }
      }

      if (archiveMailbox) {
        notes.push(
          ...(await sweepSourceToArchive(client, settings, archiveMailbox, onProgress))
        )
      } else if (settings.markSeenAfterFetch && sourceFetch.uidList.length > 0) {
        try {
          await markSeen(client, settings.mailbox, sourceFetch.uidList)
          notes.push(t('imap.markSeenOk', { count: sourceFetch.uidList.length }))
        } catch (err) {
          notes.push(t('imap.markSeenFailed', { detail: formatImapError(err) }))
        }
      }

      const doneMessage = t('imap.done', {
        newCount: fresh.reports.length,
        total: result.reports.length,
        skipped: result.skipped
      })
      const suffix = notes.length ? ` ${notes.join(' ')}` : ''

      onProgress({
        phase: 'done',
        processed: totalFetched,
        total: totalFetched,
        parsed: result.reports.length,
        skipped: result.skipped,
        message: `${doneMessage}${suffix}`
      })

      return result
    })
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
  }
}

export function previousFailingTotal(settings: ImapConnectionInput): number {
  const key = accountKeyFor(settings.user, settings.host, settings.mailbox)
  return loadCachedReports(key).meta.lastFailingTotal
}
