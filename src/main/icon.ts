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

const TRAY_ICON_SIZE = 22
/** Notification dot — matches --bad / attention cue. */
const ATTENTION_DOT = { r: 179, g: 58, b: 43, a: 255 }
const ATTENTION_RING = { r: 255, g: 255, b: 255, a: 230 }

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

/** Tray-sized app icon, optionally with a top-right attention marker. */
export function createTrayIcon(attention = false): Electron.NativeImage {
  const base = createAppIcon()
  if (base.isEmpty()) return base
  const icon = base.resize({ width: TRAY_ICON_SIZE, height: TRAY_ICON_SIZE })
  if (!attention || icon.isEmpty()) return icon
  return overlayAttentionDot(icon)
}

/** Paint a small badge in the top-right (BGRA bitmap, little-endian hosts). */
export function overlayAttentionDot(image: Electron.NativeImage): Electron.NativeImage {
  const { width, height } = image.getSize()
  if (width < 8 || height < 8) return image

  const bitmap = Buffer.from(image.toBitmap())
  const cx = width - 5
  const cy = 5
  const outerR = 5
  const innerR = 3.2

  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const dx = x + 0.5 - cx
      const dy = y + 0.5 - cy
      const dist = Math.sqrt(dx * dx + dy * dy)
      if (dist > outerR) continue

      const color = dist <= innerR ? ATTENTION_DOT : ATTENTION_RING
      const i = (y * width + x) * 4
      // nativeImage bitmaps are BGRA on little-endian.
      bitmap[i] = color.b
      bitmap[i + 1] = color.g
      bitmap[i + 2] = color.r
      bitmap[i + 3] = color.a
    }
  }

  return nativeImage.createFromBitmap(bitmap, { width, height })
}
