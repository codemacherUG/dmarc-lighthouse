import { existsSync } from 'fs'
import { join } from 'path'
import { app, nativeImage } from 'electron'

/** Prefer exact panel sizes, then larger sources the compositor can downscale. */
const ICON_CANDIDATES = [
  '64x64.png',
  '48x48.png',
  '128x128.png',
  '256x256.png',
  '512x512.png',
  '64.png',
  '48.png',
  '128.png',
  '256.png',
  '512.png'
] as const

function iconsDirectory(): string {
  if (app.isPackaged) {
    return join(process.resourcesPath, 'icons')
  }
  return join(__dirname, '../../build/icons')
}

function fallbackIconPath(): string {
  if (app.isPackaged) {
    return join(process.resourcesPath, 'app.asar.unpacked', 'resources', 'icon.png')
  }
  return join(__dirname, '../../resources/icon.png')
}

/**
 * Linux taskbars use _NET_WM_ICON bitmaps from the BrowserWindow icon.
 * createFromPath is reliable; createEmpty()+addRepresentation can stay empty
 * on some Electron/Linux builds and then the panel shows a generic gear.
 */
export function createAppIcon(): Electron.NativeImage {
  const dir = iconsDirectory()

  for (const name of ICON_CANDIDATES) {
    const file = join(dir, name)
    if (!existsSync(file)) continue
    const image = nativeImage.createFromPath(file)
    if (!image.isEmpty()) {
      return image
    }
  }

  const fallback = fallbackIconPath()
  if (existsSync(fallback)) {
    const image = nativeImage.createFromPath(fallback)
    if (!image.isEmpty()) {
      return image
    }
  }

  return nativeImage.createEmpty()
}
