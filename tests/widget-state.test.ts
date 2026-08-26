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
