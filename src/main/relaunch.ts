import { app } from 'electron'
import { existsSync, readdirSync, statSync } from 'fs'
import { basename, dirname, join } from 'path'

/**
 * After an AppImage auto-update with a versioned filename, electron-updater
 * replaces `/path/app-1.0.11.AppImage` with `/path/app-1.0.12.AppImage` but the
 * child process still inherits APPIMAGE pointing at the deleted old path.
 * Resolve a usable AppImage path (and repair process.env.APPIMAGE).
 */
export function resolveAppImagePath(
  env: NodeJS.ProcessEnv = process.env,
  opts?: {
    existsSync?: (path: string) => boolean
    readdirSync?: (path: string) => string[]
    statMtimeMs?: (path: string) => number
  }
): string | null {
  const exists = opts?.existsSync ?? existsSync
  const readdir = opts?.readdirSync ?? ((dir: string) => readdirSync(dir))
  const mtimeMs = opts?.statMtimeMs ?? ((p: string) => statSync(p).mtimeMs)

  const appImage = env.APPIMAGE?.trim()
  if (!appImage) return null
  if (exists(appImage)) return appImage

  const dir = dirname(appImage)
  if (!exists(dir)) return null

  const hint = basename(appImage).replace(/-?\d+\.\d+\.\d+.*$/i, '')
  let names: string[]
  try {
    names = readdir(dir)
  } catch {
    return null
  }

  const candidates = names
    .filter((name) => name.endsWith('.AppImage'))
    .filter((name) => !hint || name.startsWith(hint) || name.includes('dmarc'))
    .map((name) => {
      const full = join(dir, name)
      try {
        return { full, mtime: mtimeMs(full) }
      } catch {
        return null
      }
    })
    .filter((c): c is { full: string; mtime: number } => c != null)
    .sort((a, b) => b.mtime - a.mtime)

  return candidates[0]?.full ?? null
}

/** Repair APPIMAGE / portable paths so relaunch and the next update work. */
export function fixPackagedExecEnv(env: NodeJS.ProcessEnv = process.env): void {
  const resolved = resolveAppImagePath(env)
  if (resolved) env.APPIMAGE = resolved
}

/**
 * Relaunch the packaged app. Plain app.relaunch() fails for AppImage/portable
 * because process.execPath points at a temp mount that vanishes on exit.
 */
export function relaunchApp(): void {
  fixPackagedExecEnv()

  const args = process.argv.slice(1).filter((a) => a !== '--appimage-extract-and-run')
  const appImage = process.env.APPIMAGE?.trim()
  const portable = process.env.PORTABLE_EXECUTABLE_FILE?.trim()

  if (appImage && existsSync(appImage)) {
    app.relaunch({
      execPath: appImage,
      args: ['--appimage-extract-and-run', ...args]
    })
  } else if (portable && existsSync(portable)) {
    app.relaunch({ execPath: portable, args })
  } else {
    app.relaunch({ args })
  }
  app.exit(0)
}
