export type AppTheme = 'light' | 'dark' | 'auto'

export type ResolvedTheme = 'light' | 'dark'

export function normalizeTheme(value: unknown): AppTheme {
  return value === 'light' || value === 'dark' || value === 'auto' ? value : 'auto'
}

export function resolveTheme(pref: AppTheme, systemDark: boolean): ResolvedTheme {
  if (pref === 'auto') return systemDark ? 'dark' : 'light'
  return pref
}
