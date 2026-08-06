const fs = require('fs')
const path = require('path')

/**
 * Ensure AppImage/desktop theme has both:
 * - PNG sizes under hicolor/<NxN>/apps/dmarcviewer.png (panel/WM association)
 * - SVG under hicolor/scalable/apps/dmarcviewer.svg (HiDPI / file managers)
 *
 * electron-builder with linux.icon = icons should already copy PNGs; this
 * fills gaps and always installs the SVG (builder cannot mix svg+png in one icon dir).
 * Icon basename must match SAFE_STORAGE_APP_NAME / StartupWMClass (dmarcviewer).
 */
exports.default = async function afterPack(context) {
  if (context.electronPlatformName !== 'linux') return

  const projectDir = context.packager.projectDir
  const appOutDir = context.appOutDir
  const iconName = 'dmarcviewer'
  const hicolor = path.join(appOutDir, 'usr', 'share', 'icons', 'hicolor')
  const iconsSrc = path.join(projectDir, 'build', 'icons')
  const svgSrc = path.join(projectDir, 'build', 'icon.svg')

  const sizes = [16, 24, 32, 48, 64, 96, 128, 256, 512]
  for (const size of sizes) {
    const src =
      [path.join(iconsSrc, `${size}x${size}.png`), path.join(iconsSrc, `${size}.png`)].find((p) =>
        fs.existsSync(p)
      ) || null
    if (!src) continue

    const destDir = path.join(hicolor, `${size}x${size}`, 'apps')
    fs.mkdirSync(destDir, { recursive: true })
    fs.copyFileSync(src, path.join(destDir, `${iconName}.png`))
  }

  if (fs.existsSync(svgSrc)) {
    const destDir = path.join(hicolor, 'scalable', 'apps')
    fs.mkdirSync(destDir, { recursive: true })
    fs.copyFileSync(svgSrc, path.join(destDir, `${iconName}.svg`))

    const resIcons = path.join(appOutDir, 'resources', 'icons')
    fs.mkdirSync(resIcons, { recursive: true })
    fs.copyFileSync(svgSrc, path.join(resIcons, 'icon.svg'))
  }
}
