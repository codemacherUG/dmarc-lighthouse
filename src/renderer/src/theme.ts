import { normalizeTheme, resolveTheme, type AppTheme } from '../../shared/theme'
import { applyChartTheme } from './charts'
import { themeEl } from './dom'
import { invalidateIpMapSize } from './ip-map'

const THEME_MQ = window.matchMedia('(prefers-color-scheme: dark)')

let currentPref: AppTheme = 'auto'

function resolvedTheme(pref: AppTheme): 'light' | 'dark' {
  return resolveTheme(pref, THEME_MQ.matches)
}

export function applyTheme(pref: AppTheme): void {
  const next = normalizeTheme(pref)
  currentPref = next
  const resolved = resolvedTheme(next)
  document.documentElement.dataset.theme = resolved
  document.documentElement.style.colorScheme = resolved
  applyChartTheme()
  invalidateIpMapSize()
  if (typeof window.api.previewTheme === 'function') {
    void window.api.previewTheme(next)
  }
}

export function initTheme(): void {
  THEME_MQ.addEventListener('change', () => {
    if (currentPref === 'auto') applyTheme('auto')
  })
  themeEl.addEventListener('change', () => {
    applyTheme(normalizeTheme(themeEl.value))
  })
}
