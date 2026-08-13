import { app, BrowserWindow } from 'electron'
import { writeFileSync, mkdirSync, existsSync } from 'fs'
import { join } from 'path'

async function wait(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms))
}

async function ready(win: BrowserWindow): Promise<void> {
  for (let i = 0; i < 80; i++) {
    const ok = await win.webContents.executeJavaScript(
      'Boolean(window.__dmarcScreenshot && window.api)'
    )
    if (ok) return
    await wait(100)
  }
  throw new Error('Screenshot helpers did not load')
}

async function api(win: BrowserWindow, body: string): Promise<void> {
  await win.webContents.executeJavaScript(
    `(async () => {
      const api = window.__dmarcScreenshot
      if (!api) throw new Error('Screenshot helpers not loaded')
      ${body}
    })()`
  )
}

async function apiValue<T>(win: BrowserWindow, body: string): Promise<T> {
  return (await win.webContents.executeJavaScript(
    `(async () => {
      const api = window.__dmarcScreenshot
      if (!api) throw new Error('Screenshot helpers not loaded')
      ${body}
    })()`
  )) as T
}

async function capture(win: BrowserWindow, filePath: string): Promise<void> {
  await wait(500)
  const image = await win.webContents.capturePage()
  writeFileSync(filePath, image.toPNG())
  console.log(`Wrote ${filePath}`)
}

/** Full-page PNG via CDP so content taller than the display still fits. */
async function captureFullPage(win: BrowserWindow, filePath: string): Promise<void> {
  const size = await apiValue<{ width: number; height: number }>(
    win,
    'return await api.prepareFullPage()'
  )
  await captureViewport(
    win,
    filePath,
    Math.max(1200, Math.min(size.width, 1800)),
    Math.max(900, Math.min(size.height + 8, 12000))
  )
}

/** Viewport-sized PNG of the composited surface (includes modal dialogs). */
async function captureViewportExact(
  win: BrowserWindow,
  filePath: string,
  width: number,
  height: number
): Promise<void> {
  const dbg = win.webContents.debugger
  if (!dbg.isAttached()) dbg.attach('1.3')
  try {
    await dbg.sendCommand('Emulation.setDeviceMetricsOverride', {
      mobile: false,
      width,
      height,
      deviceScaleFactor: 1,
      screenWidth: width,
      screenHeight: height
    })
    await wait(600)
    const result = (await dbg.sendCommand('Page.captureScreenshot', {
      format: 'png',
      fromSurface: true
    })) as { data: string }
    writeFileSync(filePath, Buffer.from(result.data, 'base64'))
    console.log(`Wrote ${filePath} (${width}×${height})`)
  } finally {
    try {
      await dbg.sendCommand('Emulation.clearDeviceMetricsOverride')
    } catch {
      // ignore
    }
    try {
      dbg.detach()
    } catch {
      // ignore
    }
  }
}

/** Screenshot beyond the visible viewport at a fixed size. */
async function captureViewport(
  win: BrowserWindow,
  filePath: string,
  width: number,
  height: number
): Promise<void> {
  const dbg = win.webContents.debugger
  if (!dbg.isAttached()) dbg.attach('1.3')
  try {
    await dbg.sendCommand('Emulation.setDeviceMetricsOverride', {
      mobile: false,
      width,
      height,
      deviceScaleFactor: 1,
      screenWidth: width,
      screenHeight: height
    })
    await wait(600)
    const result = (await dbg.sendCommand('Page.captureScreenshot', {
      format: 'png',
      fromSurface: true,
      captureBeyondViewport: true
    })) as { data: string }
    writeFileSync(filePath, Buffer.from(result.data, 'base64'))
    console.log(`Wrote ${filePath} (${width}×${height})`)
  } finally {
    try {
      await dbg.sendCommand('Emulation.clearDeviceMetricsOverride')
    } catch {
      // ignore
    }
    try {
      dbg.detach()
    } catch {
      // ignore
    }
  }
}

/** Capture anonymized README screenshots, then quit. */
export async function runScreenshotCapture(win: BrowserWindow): Promise<void> {
  const outDir = join(process.cwd(), 'docs', 'screenshots')
  if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true })

  await ready(win)
  // Let the normal settings/cache bootstrap finish, then overwrite with demo data.
  await wait(800)

  await api(win, 'await api.prepareDemo()')
  await wait(700)

  if (wantsFullAppCapture()) {
    await captureFullPage(win, join(outDir, 'app-full.png'))
    console.log('Full-app screenshot capture complete.')
    app.exit(0)
    return
  }

  await capture(win, join(outDir, 'dashboard.png'))

  await api(
    win,
    `api.setTheme('dark')
     await new Promise((r) => setTimeout(r, 400))`
  )
  await wait(500)
  await capture(win, join(outDir, 'dashboard-dark.png'))
  await api(win, `api.setTheme('light')`)
  await wait(400)

  await api(
    win,
    `await api.selectFirstReport()
     const target = document.querySelector('.tables-panel')
     if (target) {
       // Offset for sticky app header so the volume chart is fully out of view.
       const top = target.getBoundingClientRect().top + window.scrollY - 72
       window.scrollTo({ top: Math.max(0, top), behavior: 'instant' })
     }
     await new Promise((r) => setTimeout(r, 300))`
  )
  await wait(400)
  await capture(win, join(outDir, 'tables.png'))

  await api(
    win,
    `const target = document.querySelector('.ip-map-panel')
     if (target) {
       const top = target.getBoundingClientRect().top + window.scrollY - 72
       window.scrollTo({ top: Math.max(0, top), behavior: 'instant' })
     }
     // Give Leaflet / OSM tiles a moment to paint.
     await new Promise((r) => setTimeout(r, 1200))`
  )
  await wait(800)
  await capture(win, join(outDir, 'map.png'))

  await api(win, 'api.openSettingsDemo()')
  await wait(500)
  await capture(win, join(outDir, 'settings.png'))
  await api(win, 'api.closeSettings()')

  await api(win, `api.setTheme('light')`)
  await api(win, 'api.openRolloutDemo()')
  await wait(500)
  await capture(win, join(outDir, 'rollout.png'))
  await api(win, 'api.closeRollout()')

  await api(win, 'api.openDnsDemo()')
  await wait(400)
  await capture(win, join(outDir, 'dns.png'))
  await api(win, 'api.closeDns()')

  const emailSize = await apiValue<{ width: number; height: number }>(
    win,
    'return api.openEmailInspectDemo()'
  )
  await wait(400)
  await captureViewportExact(
    win,
    join(outDir, 'email.png'),
    Math.max(900, emailSize.width + 48),
    Math.max(720, emailSize.height + 72)
  )
  await api(win, 'api.closeEmailInspect()')

  await captureFullPage(win, join(outDir, 'app-full.png'))

  console.log('Screenshot capture complete.')
  app.exit(0)
}

export function wantsScreenshotCapture(): boolean {
  return (
    process.argv.includes('--capture-screenshots') || process.argv.includes('--capture-full-app')
  )
}

export function wantsFullAppCapture(): boolean {
  return process.argv.includes('--capture-full-app')
}
