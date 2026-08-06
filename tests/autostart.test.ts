import { describe, expect, it } from 'vitest'
import {
  buildLinuxAutostartDesktop,
  quoteDesktopArg,
  resolveLinuxAutostartExecPath
} from '../src/main/autostart'

describe('quoteDesktopArg', () => {
  it('leaves simple paths unquoted', () => {
    expect(quoteDesktopArg('/opt/dmarc-lighthouse/dmarc-lighthouse')).toBe(
      '/opt/dmarc-lighthouse/dmarc-lighthouse'
    )
  })

  it('quotes paths with spaces and escapes special chars', () => {
    expect(quoteDesktopArg('/home/u/My Apps/app.AppImage')).toBe('"/home/u/My Apps/app.AppImage"')
    expect(quoteDesktopArg('/tmp/a"b')).toBe('"/tmp/a\\"b"')
  })
})

describe('resolveLinuxAutostartExecPath', () => {
  it('prefers APPIMAGE over the mounted execPath', () => {
    expect(
      resolveLinuxAutostartExecPath(
        { APPIMAGE: '/home/u/Apps/dmarc-lighthouse.AppImage' },
        '/tmp/.mount_dmarcX/dmarc-lighthouse'
      )
    ).toBe('/home/u/Apps/dmarc-lighthouse.AppImage')
  })

  it('falls back to execPath when APPIMAGE is unset', () => {
    expect(resolveLinuxAutostartExecPath({}, '/opt/dmarc-lighthouse/dmarc-lighthouse')).toBe(
      '/opt/dmarc-lighthouse/dmarc-lighthouse'
    )
  })
})

describe('buildLinuxAutostartDesktop', () => {
  it('writes a hidden autostart entry for AppImage', () => {
    const desktop = buildLinuxAutostartDesktop({
      execPath: '/home/u/Apps/dmarc-lighthouse.AppImage',
      hidden: true
    })
    expect(desktop).toContain('Exec=/home/u/Apps/dmarc-lighthouse.AppImage --hidden')
    expect(desktop).toContain('X-GNOME-Autostart-enabled=true')
    expect(desktop).toContain('StartupWMClass=dmarcviewer')
    expect(desktop).toContain('Name=DMARC Lighthouse')
  })

  it('omits --hidden when starting visible', () => {
    const desktop = buildLinuxAutostartDesktop({
      execPath: '/opt/dmarc-lighthouse/dmarc-lighthouse',
      hidden: false
    })
    expect(desktop).toContain('Exec=/opt/dmarc-lighthouse/dmarc-lighthouse\n')
    expect(desktop).not.toContain('--hidden')
  })
})
