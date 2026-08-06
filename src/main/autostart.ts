import { app } from 'electron'
import { existsSync, mkdirSync, unlinkSync, writeFileSync } from 'fs'
import { homedir } from 'os'
import { join } from 'path'

const DESKTOP_FILENAME = 'dmarc-lighthouse.desktop'
/** Pre-rename autostart entry — remove so only one login item remains. */
const LEGACY_DESKTOP_FILENAME = 'dmarcviewer.desktop'

/** Quote a single Exec argument per the Desktop Entry Spec. */
export function quoteDesktopArg(value: string): string {
  if (!/[\s"$\\`]/.test(value)) return value
  return `"${value.replace(/(["$\\`])/g, '\\$1')}"`
}

/**
 * Resolve the binary path that should be launched at login.
 * AppImage mounts under /tmp — use APPIMAGE so the entry survives reboot.
 */
export function resolveLinuxAutostartExecPath(
  env: NodeJS.ProcessEnv = process.env,
  execPath: string = process.execPath
): string {
  const appImage = env.APPIMAGE?.trim()
  if (appImage) return appImage
  return execPath
}

export function buildLinuxAutostartDesktop(opts: {
  execPath: string
  hidden: boolean
  name?: string
}): string {
  const exec = quoteDesktopArg(opts.execPath)
  const args = opts.hidden ? ' --hidden' : ''
  const name = opts.name ?? 'DMARC Lighthouse'
  return [
    '[Desktop Entry]',
    'Type=Application',
    'Version=1.0',
    `Name=${name}`,
    'Comment=DMARC aggregate and forensic report viewer',
    `Exec=${exec}${args}`,
    'Icon=dmarcviewer',
    'Terminal=false',
    'Categories=Utility;',
    'StartupWMClass=dmarcviewer',
    'X-GNOME-Autostart-enabled=true',
    ''
  ].join('\n')
}

function linuxAutostartDir(): string {
  const xdg = process.env.XDG_CONFIG_HOME?.trim()
  return xdg ? join(xdg, 'autostart') : join(homedir(), '.config', 'autostart')
}

function linuxAutostartDesktopPath(): string {
  return join(linuxAutostartDir(), DESKTOP_FILENAME)
}

function removeLegacyLinuxAutostart(): void {
  const legacy = join(linuxAutostartDir(), LEGACY_DESKTOP_FILENAME)
  if (existsSync(legacy)) unlinkSync(legacy)
}

/** Electron's login-item API is darwin/win32 only — Linux needs XDG autostart. */
export function applyLinuxOpenAtLogin(openAtLogin: boolean, openAsHidden: boolean): void {
  removeLegacyLinuxAutostart()
  const desktopPath = linuxAutostartDesktopPath()

  if (!openAtLogin) {
    if (existsSync(desktopPath)) unlinkSync(desktopPath)
    return
  }

  // Dev would register the electron binary; only wire packaged builds.
  if (!app.isPackaged) return

  const execPath = resolveLinuxAutostartExecPath()
  const dir = linuxAutostartDir()
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
  writeFileSync(desktopPath, buildLinuxAutostartDesktop({ execPath, hidden: openAsHidden }), 'utf8')
}
