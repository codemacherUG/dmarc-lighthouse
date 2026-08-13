import { describe, expect, it } from 'vitest'
import { normalizeTheme, resolveTheme } from '../src/shared/theme'

describe('normalizeTheme', () => {
  it('keeps valid values', () => {
    expect(normalizeTheme('light')).toBe('light')
    expect(normalizeTheme('dark')).toBe('dark')
    expect(normalizeTheme('auto')).toBe('auto')
  })

  it('falls back to auto', () => {
    expect(normalizeTheme(undefined)).toBe('auto')
    expect(normalizeTheme('system')).toBe('auto')
    expect(normalizeTheme('')).toBe('auto')
  })
})

describe('resolveTheme', () => {
  it('follows the OS in auto mode', () => {
    expect(resolveTheme('auto', true)).toBe('dark')
    expect(resolveTheme('auto', false)).toBe('light')
  })

  it('ignores the OS when a scheme is chosen', () => {
    expect(resolveTheme('light', true)).toBe('light')
    expect(resolveTheme('dark', false)).toBe('dark')
  })
})
