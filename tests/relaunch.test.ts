import { describe, expect, it } from 'vitest'
import { resolveAppImagePath } from '../src/main/relaunch'

describe('resolveAppImagePath', () => {
  it('returns APPIMAGE when the file still exists', () => {
    const path = resolveAppImagePath(
      { APPIMAGE: '/home/u/Apps/dmarc-lighthouse-1.0.11-linux.AppImage' },
      {
        existsSync: (p) => p === '/home/u/Apps/dmarc-lighthouse-1.0.11-linux.AppImage',
        readdirSync: () => [],
        statMtimeMs: () => 0
      }
    )
    expect(path).toBe('/home/u/Apps/dmarc-lighthouse-1.0.11-linux.AppImage')
  })

  it('finds the newest sibling AppImage after a versioned rename', () => {
    const dir = '/home/u/Apps'
    const oldPath = `${dir}/dmarc-lighthouse-1.0.11-linux.AppImage`
    const newer = `${dir}/dmarc-lighthouse-1.0.12-linux.AppImage`
    const olderOther = `${dir}/dmarc-lighthouse-1.0.10-linux.AppImage`
    const path = resolveAppImagePath(
      { APPIMAGE: oldPath },
      {
        existsSync: (p) => p === dir || p === newer || p === olderOther,
        readdirSync: () => [
          'dmarc-lighthouse-1.0.10-linux.AppImage',
          'dmarc-lighthouse-1.0.12-linux.AppImage',
          'notes.txt'
        ],
        statMtimeMs: (p) => (p === newer ? 200 : 100)
      }
    )
    expect(path).toBe(newer)
  })

  it('returns null when APPIMAGE is unset', () => {
    expect(resolveAppImagePath({}, { existsSync: () => false })).toBeNull()
  })
})
