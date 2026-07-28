import { ImapFlow } from 'imapflow'
import type { AnalyzeProgress, ImapConnectionInput, TestConnectionResult } from '../shared/types'
import { parseMimeSources } from './analyze'

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
      const exists = client.mailbox && typeof client.mailbox === 'object' ? client.mailbox.exists : 0
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

export async function fetchAndAnalyze(
  settings: ImapConnectionInput,
  onProgress: ProgressCallback
): Promise<Awaited<ReturnType<typeof parseMimeSources>>> {
  const client = createClient(settings)

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
        message: 'Suche DMARC-Reports…'
      })

      const filter = settings.subjectFilter.trim()
      const searchQuery = filter ? { subject: filter } : { all: true as const }
      const uids = await client.search(searchQuery, { uid: true })

      if (!uids || uids.length === 0) {
        onProgress({
          phase: 'done',
          processed: 0,
          total: 0,
          parsed: 0,
          skipped: 0,
          message: 'Keine passenden Nachrichten gefunden.'
        })
        return {
          aggregate: {
            reportCount: 0,
            total: 0,
            passing: 0,
            failing: 0,
            passRate: 0,
            dateBegin: null,
            dateEnd: null,
            domains: []
          },
          dashboard: {
            dmarc: { pass: 0, fail: 0, other: 0 },
            spf: { pass: 0, fail: 0, other: 0 },
            dkim: { pass: 0, fail: 0, other: 0 },
            dispositions: [],
            byOrg: [],
            bySourceIp: [],
            byHeaderFrom: [],
            volumeByDay: []
          },
          reports: [],
          skipped: 0,
          errors: []
        }
      }

      const total = uids.length
      onProgress({
        phase: 'fetching',
        processed: 0,
        total,
        parsed: 0,
        skipped: 0,
        message: `${total} Nachrichten werden geladen…`
      })

      const sources: Array<{ uid: number; source: Buffer }> = []
      let processed = 0

      for await (const message of client.fetch(
        uids,
        { uid: true, source: true },
        { uid: true }
      )) {
        processed += 1
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

      const result = await parseMimeSources(sources)

      onProgress({
        phase: 'done',
        processed: total,
        total,
        parsed: result.reports.length,
        skipped: result.skipped,
        message: `${result.reports.length} Reports, ${result.skipped} übersprungen.`
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
