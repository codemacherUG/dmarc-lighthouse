import { describe, expect, it } from 'vitest'
import {
  readCollapsedWidgetIds,
  WIDGET_COLLAPSE_STORAGE_KEY,
  writeCollapsedWidgetIds
} from '../src/renderer/src/widget-state'
import {
  findSpfPrefixesForDomain,
  problemSourceIgnoreKey,
  PROBLEM_SOURCE_IGNORE_STORAGE_KEY,
  readIgnoredProblemSourceKeys,
  writeIgnoredProblemSourceKeys
} from '../src/renderer/src/problem-source-state'
import {
  ampelQuickActionsForReasons,
  DASHBOARD_UI_STATE_STORAGE_KEY,
  DEFAULT_DASHBOARD_UI_STATE,
  filterAndSortDomainHealth,
  readDashboardUiState,
  writeDashboardUiState
} from '../src/renderer/src/dashboard-ui-state'
import type { DomainHealth } from '../src/shared/types'

describe('widget collapse state', () => {
  it('round-trips collapsed widget ids in stable order', () => {
    let storedValue: string | null = null
    const storage = {
      getItem: (key: string): string | null =>
        key === WIDGET_COLLAPSE_STORAGE_KEY ? storedValue : null,
      setItem: (key: string, value: string): void => {
        if (key === WIDGET_COLLAPSE_STORAGE_KEY) storedValue = value
      }
    }

    writeCollapsedWidgetIds(storage, new Set(['reports', 'charts']))

    expect(storedValue).toBe('["charts","reports"]')
    expect(readCollapsedWidgetIds(storage)).toEqual(new Set(['charts', 'reports']))
  })

  it('ignores malformed and non-list values', () => {
    const malformed = { getItem: (): string => '{', setItem: (): void => undefined }
    const objectValue = { getItem: (): string => '{}', setItem: (): void => undefined }

    expect(readCollapsedWidgetIds(malformed)).toEqual(new Set())
    expect(readCollapsedWidgetIds(objectValue)).toEqual(new Set())
  })

  it('keeps only non-empty string ids', () => {
    const storage = {
      getItem: (): string => '["summary",42,"",null,"summary"]',
      setItem: (): void => undefined
    }

    expect(readCollapsedWidgetIds(storage)).toEqual(new Set(['summary']))
  })

  it('tolerates unavailable storage', () => {
    const storage = {
      getItem: (): string => {
        throw new Error('blocked')
      },
      setItem: (): void => {
        throw new Error('blocked')
      }
    }

    expect(readCollapsedWidgetIds(storage)).toEqual(new Set())
    expect(() => writeCollapsedWidgetIds(storage, new Set(['summary']))).not.toThrow()
  })
})

describe('problem source ignore state', () => {
  it('never borrows SPF prefixes from another monitored domain', () => {
    const microsoftPrefix = [{ family: 4 as const, base: 0x285d0000, bits: 16 }]
    const prefixesByDomain = new Map([['other.example', microsoftPrefix]])

    expect(findSpfPrefixesForDomain(prefixesByDomain, 'science2public.com')).toEqual([])
    expect(findSpfPrefixesForDomain(prefixesByDomain, 'mail.other.example')).toBe(microsoftPrefix)
  })

  it('keeps ignored sources separate per account', () => {
    let storedValue: string | null = null
    const storage = {
      getItem: (key: string): string | null =>
        key === PROBLEM_SOURCE_IGNORE_STORAGE_KEY ? storedValue : null,
      setItem: (key: string, value: string): void => {
        if (key === PROBLEM_SOURCE_IGNORE_STORAGE_KEY) storedValue = value
      }
    }

    writeIgnoredProblemSourceKeys(storage, 'account-a', new Set(['example.com|40.93.78.51']))
    writeIgnoredProblemSourceKeys(storage, 'account-b', new Set(['example.net|203.0.113.5']))

    expect(readIgnoredProblemSourceKeys(storage, 'account-a')).toEqual(
      new Set(['example.com|40.93.78.51'])
    )
    expect(readIgnoredProblemSourceKeys(storage, 'account-b')).toEqual(
      new Set(['example.net|203.0.113.5'])
    )
  })

  it('normalizes the source key and tolerates malformed storage', () => {
    expect(problemSourceIgnoreKey(' 40.93.78.51 ', ' Science2Public.COM ')).toBe(
      'science2public.com|40.93.78.51'
    )
    expect(
      readIgnoredProblemSourceKeys(
        { getItem: (): string => '{', setItem: (): void => undefined },
        'account-a'
      )
    ).toEqual(new Set())
  })
})

describe('dashboard UI state & Domain-Ampel filtering/sorting', () => {
  it('persists and merges dashboard filter preferences safely', () => {
    let storedValue: string | null = null
    const storage = {
      getItem: (key: string): string | null =>
        key === DASHBOARD_UI_STATE_STORAGE_KEY ? storedValue : null,
      setItem: (key: string, value: string): void => {
        if (key === DASHBOARD_UI_STATE_STORAGE_KEY) storedValue = value
      }
    }

    expect(readDashboardUiState(storage)).toEqual(DEFAULT_DASHBOARD_UI_STATE)

    writeDashboardUiState(storage, { range: '90', domain: ' example.com ', ampelCompact: true })
    writeDashboardUiState(storage, { disposition: 'reject', ampelSort: 'passRateAsc' })

    expect(readDashboardUiState(storage)).toEqual({
      range: '90',
      disposition: 'reject',
      domain: 'example.com',
      ampelSort: 'passRateAsc',
      ampelCompact: true
    })

    // Invalid custom range or malformed values fall back to defaults.
    storedValue = JSON.stringify({ range: 'custom', disposition: 'invalid', ampelSort: 'bogus' })
    expect(readDashboardUiState(storage)).toEqual(DEFAULT_DASHBOARD_UI_STATE)
  })

  it('filters and sorts Domain-Ampel rows by status, query, pass rate, volume, and domain', () => {
    const sample: DomainHealth[] = [
      {
        domain: 'zeta.example',
        total: 50,
        passing: 50,
        failing: 0,
        passRate: 100,
        dkimSelectors: [],
        dkimVerifiedSelectors: [],
        dmarcPolicy: 'reject',
        spfOk: true,
        dkimOk: true,
        status: 'ok',
        reasons: ['health.reason.ok']
      },
      {
        domain: 'alpha.example',
        total: 200,
        passing: 190,
        failing: 10,
        passRate: 95,
        dkimSelectors: [],
        dkimVerifiedSelectors: [],
        dmarcPolicy: 'none',
        spfOk: true,
        dkimOk: true,
        status: 'warn',
        reasons: ['health.reason.policyNone', 'health.reason.passRateWarn']
      },
      {
        domain: 'beta.example',
        total: 80,
        passing: 60,
        failing: 20,
        passRate: 75,
        dkimSelectors: [],
        dkimVerifiedSelectors: [],
        dmarcPolicy: null,
        spfOk: false,
        dkimOk: false,
        status: 'bad',
        reasons: ['health.reason.noDmarc', 'health.reason.spfInvalid']
      }
    ]

    expect(filterAndSortDomainHealth(sample, { sort: 'status' }).map((r) => r.domain)).toEqual([
      'beta.example',
      'alpha.example',
      'zeta.example'
    ])
    expect(
      filterAndSortDomainHealth(sample, { statusFilter: 'warn' }).map((r) => r.domain)
    ).toEqual(['alpha.example'])
    expect(filterAndSortDomainHealth(sample, { query: 'permerror' }).map((r) => r.domain)).toEqual([
      'beta.example'
    ])
    expect(filterAndSortDomainHealth(sample, { sort: 'passRateAsc' }).map((r) => r.domain)).toEqual(
      ['beta.example', 'alpha.example', 'zeta.example']
    )
    expect(filterAndSortDomainHealth(sample, { sort: 'volumeDesc' }).map((r) => r.domain)).toEqual([
      'alpha.example',
      'beta.example',
      'zeta.example'
    ])
    expect(filterAndSortDomainHealth(sample, { sort: 'domainAsc' }).map((r) => r.domain)).toEqual([
      'alpha.example',
      'beta.example',
      'zeta.example'
    ])
  })

  it('maps domain-health reasons to deduplicated wizard quick-actions', () => {
    expect(
      ampelQuickActionsForReasons([
        'health.reason.noDmarc',
        'health.reason.noSpf',
        'health.reason.spfInvalid',
        'health.reason.policyNone',
        'health.reason.dkimMissing'
      ]).map((a) => a.action)
    ).toEqual(['dmarc', 'spf', 'rollout', 'dkim'])
    expect(ampelQuickActionsForReasons(['health.reason.ok'])).toEqual([])
  })
})
