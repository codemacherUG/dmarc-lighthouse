import { describe, expect, it } from 'vitest'
import {
  LEGACY_SAFE_STORAGE_APP_NAME,
  SAFE_STORAGE_APP_NAME,
  resolveSafeStorageAppName,
  resolveUserDataDir
} from '../src/main/app-identity'

describe('resolveSafeStorageAppName', () => {
  it('defaults to the stable historical name', () => {
    expect(resolveSafeStorageAppName({})).toBe(SAFE_STORAGE_APP_NAME)
  })

  it('honors the marker for either historical name', () => {
    expect(resolveSafeStorageAppName({ markerContents: LEGACY_SAFE_STORAGE_APP_NAME })).toBe(
      LEGACY_SAFE_STORAGE_APP_NAME
    )
    expect(resolveSafeStorageAppName({ markerContents: `${SAFE_STORAGE_APP_NAME}\n` })).toBe(
      SAFE_STORAGE_APP_NAME
    )
  })

  it('forces the stable name while a migrate file is pending', () => {
    expect(
      resolveSafeStorageAppName({
        markerContents: LEGACY_SAFE_STORAGE_APP_NAME,
        migratePending: true
      })
    ).toBe(SAFE_STORAGE_APP_NAME)
  })
})

describe('resolveUserDataDir', () => {
  it('prefers a candidate that already has settings.json', () => {
    const chosen = resolveUserDataDir({
      appData: '/home/u/.config',
      hasSettings: (dir) => dir.endsWith('DMARC Viewer'),
      candidates: ['dmarcviewer', 'DMARC Viewer', 'dmarc-lighthouse']
    })
    expect(chosen).toBe('/home/u/.config/DMARC Viewer')
  })

  it('falls back to an existing directory without settings', () => {
    const existing = new Set(['/home/u/.config/dmarc-lighthouse'])
    const chosen = resolveUserDataDir({
      appData: '/home/u/.config',
      hasSettings: () => false,
      dirExists: (dir) => existing.has(dir),
      candidates: ['dmarcviewer', 'dmarc-lighthouse']
    })
    expect(chosen).toBe('/home/u/.config/dmarc-lighthouse')
  })
})
