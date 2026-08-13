import type { AppLocale } from './i18n'

export interface ReportPeriod {
  /** Inclusive start (ISO). */
  from: string
  /** Exclusive end (ISO) — the first instant of the following month. */
  to: string
  /** `YYYY-MM` of the covered month. */
  month: string
}

/** Calendar month `monthIndex` (0 = January) in local time. */
export function monthRange(year: number, monthIndex: number): ReportPeriod {
  const start = new Date(year, monthIndex, 1, 0, 0, 0, 0)
  const end = new Date(year, monthIndex + 1, 1, 0, 0, 0, 0)
  const month = `${start.getFullYear()}-${String(start.getMonth() + 1).padStart(2, '0')}`
  return { from: start.toISOString(), to: end.toISOString(), month }
}

/** Calendar month before `now`, in local time — the period a monthly run covers. */
export function previousMonthRange(now: Date = new Date()): ReportPeriod {
  return monthRange(now.getFullYear(), now.getMonth() - 1)
}

/**
 * Previous calendar month if any timestamp falls into it; otherwise the month
 * of the latest timestamp. Used by “generate now” so domains that only appeared
 * this month still get a PDF.
 */
export function periodForReports(
  timestamps: string[],
  now: Date = new Date()
): ReportPeriod | null {
  const prev = previousMonthRange(now)
  const from = Date.parse(prev.from)
  const to = Date.parse(prev.to)
  if (
    timestamps.some((iso) => {
      const t = Date.parse(iso)
      return !Number.isNaN(t) && t >= from && t < to
    })
  ) {
    return prev
  }
  let latest = 0
  for (const iso of timestamps) {
    const t = Date.parse(iso)
    if (!Number.isNaN(t) && t > latest) latest = t
  }
  if (!latest) return null
  const date = new Date(latest)
  return monthRange(date.getFullYear(), date.getMonth())
}

/**
 * A monthly run is due once per calendar month: the previous month must be
 * complete and not yet reported. Without a last run we report immediately so a
 * freshly enabled schedule delivers something instead of waiting a month.
 */
export function isMonthlyReportDue(lastRunIso: string | null, now: Date = new Date()): boolean {
  const period = previousMonthRange(now)
  if (!lastRunIso) return true
  const last = new Date(lastRunIso)
  if (Number.isNaN(last.getTime())) return true
  // The run stamp lies in the month after the reported one, so anything before
  // the end of the period means that month has not been reported yet.
  return last.getTime() < new Date(period.to).getTime()
}

/** Localized month name plus year, e.g. "Juli 2026". */
export function monthLabel(month: string, locale: AppLocale): string {
  const [yearRaw, monthRaw] = month.split('-')
  const year = Number(yearRaw)
  const index = Number(monthRaw) - 1
  if (!Number.isFinite(year) || !Number.isFinite(index)) return month
  const date = new Date(year, index, 1)
  const name = new Intl.DateTimeFormat(locale === 'de' ? 'de-DE' : 'en-US', {
    month: 'long'
  }).format(date)
  return `${name} ${year}`
}

/** File name for a monthly PDF, e.g. `dmarc-report-example.com-2026-07.pdf`. */
export function monthlyReportFilename(domain: string | null, month: string): string {
  const slug = (domain ?? 'all-domains')
    .toLowerCase()
    .replace(/[^a-z0-9.-]+/g, '-')
    .replace(/^-+|-+$/g, '')
  return `dmarc-report-${slug || 'all-domains'}-${month}.pdf`
}
