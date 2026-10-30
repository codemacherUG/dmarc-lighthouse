import { de, type MessageKey } from './locales/de'
import { en } from './locales/en'

export type AppLocale = 'de' | 'en'
export type { MessageKey }

type Dict = Record<MessageKey, string>

const catalogs: Record<AppLocale, Dict> = { de, en }

let currentLocale: AppLocale = 'de'

export function normalizeLocale(value: unknown): AppLocale {
  return value === 'en' ? 'en' : 'de'
}

export function detectSystemLocale(raw?: string): AppLocale {
  const locale = (raw ?? '').toLowerCase()
  return locale.startsWith('de') ? 'de' : 'en'
}

export function getLocale(): AppLocale {
  return currentLocale
}

export function setLocale(locale: AppLocale): void {
  currentLocale = normalizeLocale(locale)
}

export function t(
  key: MessageKey,
  params?: Record<string, string | number>,
  locale: AppLocale = currentLocale
): string {
  const catalog = catalogs[locale] ?? catalogs.de
  let text = catalog[key] ?? catalogs.de[key] ?? String(key)
  if (params) {
    for (const [name, value] of Object.entries(params)) {
      text = text.replaceAll(`{${name}}`, String(value))
    }
  }
  return text
}
