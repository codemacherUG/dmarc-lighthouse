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

async function capture(win: BrowserWindow, filePath: string): Promise<void> {
  await wait(500)
  const image = await win.webContents.capturePage()
  writeFileSync(filePath, image.toPNG())
  console.log(`Wrote ${filePath}`)
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
  await capture(win, join(outDir, 'dashboard.png'))

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

  console.log('Screenshot capture complete.')
  app.exit(0)
}

export function wantsScreenshotCapture(): boolean {
  return process.argv.includes('--capture-screenshots')
}
