import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { afterEach, describe, expect, it } from 'vitest'
import {
  LOCAL_IMPORT_ACCOUNT_KEY,
  clearCache,
  closeCacheDb,
  importReports,
  loadCachedReports,
  mergeReports,
  saveCache,
  setCacheUserDataForTests
} from '../src/main/cache'
import type { ReportRow } from '../src/shared/types'

function sampleReport(id: string): ReportRow {
  return {
    reportId: id,
    orgName: 'google.com',
    domain: 'example.com',
    dateBegin: '2026-07-01T00:00:00.000Z',
    dateEnd: '2026-07-02T00:00:00.000Z',
    total: 2,
    passing: 1,
    failing: 1,
    passRate: 50,
    policyP: 'none',
    records: [
      {
        sourceIp: '192.0.2.1',
        count: 1,
        disposition: 'none',
        dkimResult: 'pass',
        spfResult: 'pass',
        headerFrom: 'example.com',
        dkimDomain: 'example.com',
        spfDomain: 'example.com',
        dkimSelectors: ['s1'],
        passesDmarc: true,
        reasons: []
      }
    ]
  }
}

describe('sqlite cache', () => {
  let dir: string

  afterEach(() => {
    closeCacheDb()
    setCacheUserDataForTests(null)
    if (dir) rmSync(dir, { recursive: true, force: true })
  })

  it('saves and loads reports + forensic rows', () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-cache-'))
    setCacheUserDataForTests(dir)

    saveCache({
      accountKey: 'acct1',
      reports: [sampleReport('r1')],
      forensicReports: [
        {
          id: 'f1',
          reportId: null,
          orgName: 'google.com',
          reportedDomain: 'example.com',
          arrivalDate: '2026-07-30T10:00:00.000Z',
          sourceIp: '203.0.113.1',
          authFailure: 'dmarc',
          deliveryResult: 'delivered',
          envelopeFrom: 'a@evil.example',
          headerFrom: 'a@evil.example',
          originalRcptTo: 'u@example.com',
          authenticationResults: 'dmarc=fail',
          subject: 'Hi',
          feedbackType: 'auth-failure'
        }
      ],
      lastUid: 42,
      lastUidArchive: 7,
      lastFailingTotal: 1,
      knownSourceIps: ['192.0.2.1']
    })

    const loaded = loadCachedReports('acct1')
    expect(loaded.meta.lastUid).toBe(42)
    expect(loaded.meta.lastUidArchive).toBe(7)
    expect(loaded.meta.knownSourceIps).toEqual(['192.0.2.1', '203.0.113.1'])
    expect(loaded.reports).toHaveLength(1)
    expect(loaded.reports[0].records[0].dkimSelectors).toEqual(['s1'])
    expect(loaded.forensicReports).toHaveLength(1)
    expect(loaded.forensicReports[0].sourceIp).toBe('203.0.113.1')
  })

  it('migrates legacy JSON cache files', () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-cache-'))
    const cacheDir = join(dir, 'cache')
    mkdirSync(cacheDir, { recursive: true })
    writeFileSync(
      join(cacheDir, 'legacykey.json'),
      JSON.stringify({
        version: 1,
        accountKey: 'legacykey',
        lastUid: 9,
        lastFetchAt: '2026-07-01T00:00:00.000Z',
        lastFailingTotal: 3,
        knownSourceIps: ['10.0.0.1'],
        reports: [sampleReport('legacy-r')]
      })
    )
    setCacheUserDataForTests(dir)

    const loaded = loadCachedReports('legacykey')
    expect(loaded.reports[0].reportId).toBe('legacy-r')
    expect(loaded.meta.lastUid).toBe(9)
    expect(loaded.meta.knownSourceIps).toEqual(['10.0.0.1'])
  })

  it('clears an account cache', () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-cache-'))
    setCacheUserDataForTests(dir)
    saveCache({
      accountKey: 'acct1',
      reports: [sampleReport('r1')],
      lastUid: 5,
      lastFailingTotal: 1,
      knownSourceIps: ['192.0.2.1']
    })
    clearCache('acct1')
    const loaded = loadCachedReports('acct1')
    expect(loaded.reports).toEqual([])
    expect(loaded.meta.lastUid).toBe(0)
  })

  it('merges reports by reportId', () => {
    const merged = mergeReports([sampleReport('a')], [sampleReport('a'), sampleReport('b')])
    expect(merged.map((r) => r.reportId).sort()).toEqual(['a', 'b'])
  })

  it('imports reports without touching the UID watermarks', () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-cache-'))
    setCacheUserDataForTests(dir)
    saveCache({
      accountKey: 'acct1',
      reports: [sampleReport('r1')],
      lastUid: 42,
      lastUidArchive: 7,
      lastFailingTotal: 1,
      knownSourceIps: ['192.0.2.1']
    })

    const imported = sampleReport('r2')
    imported.records = [{ ...imported.records[0], sourceIp: '198.51.100.9' }]
    const stored = importReports({ accountKey: 'acct1', reports: [imported] })

    expect(stored).toEqual({ addedReports: 1, updatedReports: 0, addedForensic: 0 })
    const loaded = loadCachedReports('acct1')
    expect(loaded.reports.map((r) => r.reportId).sort()).toEqual(['r1', 'r2'])
    expect(loaded.meta.lastUid).toBe(42)
    expect(loaded.meta.lastUidArchive).toBe(7)
    expect(loaded.meta.knownSourceIps).toEqual(['192.0.2.1', '198.51.100.9'])
    // Failing baseline follows the cache so imported failures do not trigger alerts.
    expect(loaded.meta.lastFailingTotal).toBe(2)
  })

  it('replaces an already cached report on re-import', () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-cache-'))
    setCacheUserDataForTests(dir)
    importReports({ accountKey: 'acct1', reports: [sampleReport('r1')] })

    const again = sampleReport('r1')
    again.records = [...again.records, { ...again.records[0], sourceIp: '198.51.100.9' }]
    const stored = importReports({ accountKey: 'acct1', reports: [again] })

    expect(stored).toEqual({ addedReports: 0, updatedReports: 1, addedForensic: 0 })
    const loaded = loadCachedReports('acct1')
    expect(loaded.reports).toHaveLength(1)
    expect(loaded.reports[0].records).toHaveLength(2)
  })

  it('imports into a fresh account slot', () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-cache-'))
    setCacheUserDataForTests(dir)
    importReports({
      accountKey: LOCAL_IMPORT_ACCOUNT_KEY,
      reports: [sampleReport('r1')]
    })
    const loaded = loadCachedReports(LOCAL_IMPORT_ACCOUNT_KEY)
    expect(loaded.reports).toHaveLength(1)
    expect(loaded.meta.lastUid).toBe(0)
  })

  it('appends newly saved reports without dropping the rest', () => {
    dir = mkdtempSync(join(tmpdir(), 'dmarc-cache-'))
    setCacheUserDataForTests(dir)
    saveCache({
      accountKey: 'acct1',
      reports: [sampleReport('r1')],
      lastUid: 1,
      lastFailingTotal: 1,
      knownSourceIps: ['192.0.2.1']
    })
    const second = sampleReport('r2')
    second.records = [{ ...second.records[0], sourceIp: '198.51.100.9' }]
    saveCache({
      accountKey: 'acct1',
      reports: [second],
      lastUid: 9,
      lastFailingTotal: 2,
      knownSourceIps: ['198.51.100.9']
    })

    const loaded = loadCachedReports('acct1')
    expect(loaded.reports.map((r) => r.reportId).sort()).toEqual(['r1', 'r2'])
    expect(loaded.reports.find((r) => r.reportId === 'r1')?.records[0].sourceIp).toBe('192.0.2.1')
    expect(loaded.reports.find((r) => r.reportId === 'r2')?.records[0].sourceIp).toBe(
      '198.51.100.9'
    )
    expect(loaded.meta.lastUid).toBe(9)
    expect(loaded.meta.knownSourceIps).toEqual(['192.0.2.1', '198.51.100.9'])
  })
})
