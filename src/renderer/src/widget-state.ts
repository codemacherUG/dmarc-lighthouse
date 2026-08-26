export const WIDGET_COLLAPSE_STORAGE_KEY = 'dmarc-lighthouse.collapsed-widgets.v1'

type WidgetStateStorage = Pick<Storage, 'getItem' | 'setItem'>

export function readCollapsedWidgetIds(storage: WidgetStateStorage | null): Set<string> {
  if (!storage) return new Set()
  try {
    const value: unknown = JSON.parse(storage.getItem(WIDGET_COLLAPSE_STORAGE_KEY) ?? '[]')
    if (!Array.isArray(value)) return new Set()
    return new Set(
      value.filter(
        (widgetId): widgetId is string => typeof widgetId === 'string' && widgetId !== ''
      )
    )
  } catch {
    return new Set()
  }
}

export function writeCollapsedWidgetIds(
  storage: WidgetStateStorage | null,
  widgetIds: ReadonlySet<string>
): void {
  if (!storage) return
  try {
    storage.setItem(WIDGET_COLLAPSE_STORAGE_KEY, JSON.stringify([...widgetIds].sort()))
  } catch {
    // The dashboard remains usable when web storage is unavailable.
  }
}
