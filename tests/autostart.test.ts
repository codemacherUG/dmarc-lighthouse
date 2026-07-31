import { describe, expect, it } from 'vitest'
import {
  buildLinuxAutostartDesktop,
  quoteDesktopArg,
  resolveLinuxAutostartExecPath
} from '../src/main/autostart'

describe('quoteDesktopArg', () => {
  it('leaves simple paths unquoted', () => {
    expect(quoteDesktopArg('/opt/dmarcviewer/dmarcviewer')).toBe('/opt/dmarcviewer/dmarcviewer')
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
        { APPIMAGE: '/home/u/Apps/dmarcviewer.AppImage' },
        '/tmp/.mount_dmarcX/dmarcviewer'
      )
    ).toBe('/home/u/Apps/dmarcviewer.AppImage')
  })

  it('falls back to execPath when APPIMAGE is unset', () => {
    expect(resolveLinuxAutostartExecPath({}, '/opt/dmarcviewer/dmarcviewer')).toBe(
      '/opt/dmarcviewer/dmarcviewer'
    )
  })
})

describe('buildLinuxAutostartDesktop', () => {
  it('writes a hidden autostart entry for AppImage', () => {
    const desktop = buildLinuxAutostartDesktop({
      execPath: '/home/u/Apps/dmarcviewer.AppImage',
      hidden: true
    })
    expect(desktop).toContain('Exec=/home/u/Apps/dmarcviewer.AppImage --hidden')
    expect(desktop).toContain('X-GNOME-Autostart-enabled=true')
    expect(desktop).toContain('StartupWMClass=dmarcviewer')
  })

  it('omits --hidden when starting visible', () => {
    const desktop = buildLinuxAutostartDesktop({
      execPath: '/opt/dmarcviewer/dmarcviewer',
      hidden: false
    })
    expect(desktop).toContain('Exec=/opt/dmarcviewer/dmarcviewer\n')
    expect(desktop).not.toContain('--hidden')
  })
})
